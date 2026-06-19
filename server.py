"""
Servidor Flask para App Facturas Recibidas.
Persistencia histórica en SQLite.
Soporta: individual, múltiples archivos y lectura de carpeta.
"""

import os
import io
import uuid
import base64
import json
import sqlite3
from flask import Flask, render_template, request, send_file, jsonify
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import qrcode
from cfdi_parser import parse_cfdi, validate_cfdi_40

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024  # 256 MB for batch

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response
DB_PATH = os.getenv('DB_PATH', os.path.join(os.path.dirname(__file__), 'cfdi_data.db'))

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    """Inicializa la base de datos SQLite y realiza limpieza de duplicados."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cfdi_records (
            id TEXT PRIMARY KEY,
            filename TEXT,
            emisor_nombre TEXT,
            emisor_rfc TEXT,
            receptor_nombre TEXT,
            receptor_rfc TEXT,
            fecha TEXT,
            fecha_fmt TEXT,
            metodo_pago TEXT,
            metodo_pago_desc TEXT,
            forma_pago TEXT,
            forma_pago_desc TEXT,
            total REAL,
            total_fmt TEXT,
            moneda TEXT,
            uuid TEXT,
            serie_folio TEXT,
            tipo TEXT,
            valid INTEGER,
            errors TEXT,
            warnings TEXT,
            xml_content BLOB,
            parsed_json TEXT,
            tipo_comprobante TEXT,
            lugar_expedicion TEXT,
            regimen_fiscal_emisor TEXT,
            subtotal REAL,
            descuento REAL,
            iva_16 REAL,
            iva_8 REAL,
            iva_0 REAL,
            iva_ret REAL,
            isr_ret REAL,
            ieps REAL
        )
    ''')

    try:
        cursor.execute('''
            DELETE FROM cfdi_records 
            WHERE id NOT IN (
                SELECT MAX(id) FROM cfdi_records GROUP BY uuid
            ) AND uuid IS NOT NULL AND uuid != ''
        ''')
    except:
        pass
        
    conn.commit()
    conn.close()

init_db()

def generate_qr_base64(url):
    if not url:
        return None
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='#0f172a', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

def get_cfdi_html(cfdi_data):
    """Genera solo el HTML para previsualización o impresión (RÁPIDO)."""
    qr_image = generate_qr_base64(cfdi_data.get('qr_url', ''))
    tpl_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(tpl_dir))
    template = env.get_template('cfdi_pdf.html')
    html_content = template.render(
        comprobante=cfdi_data['comprobante'],
        emisor=cfdi_data['emisor'],
        receptor=cfdi_data['receptor'],
        conceptos=cfdi_data['conceptos'],
        impuestos=cfdi_data['impuestos'],
        timbre=cfdi_data['timbre'],
        cadena_original=cfdi_data['cadena_original'],
        qr_url=cfdi_data.get('qr_url', ''),
        qr_image=qr_image,
    )
    return html_content

def generate_pdf_from_html(html_content):
    """Convierte HTML a PDF usando WeasyPrint (PESADO)."""
    return HTML(string=html_content).write_pdf()

def parse_and_save(xml_bytes, filename, external_conn=None):
    """
    Parsea un XML y lo guarda. 
    Si se pasa external_conn, no hace commit ni cierra para permitir transacciones masivas.
    """
    try:
        import hashlib
        data = parse_cfdi(xml_bytes)
        validation = validate_cfdi_40(data)
        res = data.get('resumen_fiscal', {})
        
        fiscal_uuid = data['timbre'].get('UUID', '').upper()
        if fiscal_uuid:
            entry_id = fiscal_uuid
        else:
            # Si no hay UUID, usamos un hash del contenido para evitar duplicados del mismo archivo
            entry_id = "HASH_" + hashlib.md5(xml_bytes).hexdigest()
        
        row = {
            'id': entry_id,
            'filename': filename,
            'emisor_nombre': data['emisor'].get('Nombre', ''),
            'emisor_rfc': data['emisor'].get('Rfc', ''),
            'receptor_nombre': data['receptor'].get('Nombre', ''),
            'receptor_rfc': data['receptor'].get('Rfc', ''),
            'fecha': data['comprobante'].get('Fecha', ''),
            'fecha_fmt': data['comprobante'].get('FechaFmt', ''),
            'metodo_pago': data['comprobante'].get('MetodoPago', ''),
            'metodo_pago_desc': data['comprobante'].get('MetodoPagoDesc', ''),
            'forma_pago': data['comprobante'].get('FormaPago', ''),
            'forma_pago_desc': data['comprobante'].get('FormaPagoDesc', ''),
            'total': float(data['comprobante'].get('Total', 0)),
            'total_fmt': data['comprobante'].get('TotalFmt', '$0.00'),
            'moneda': data['comprobante'].get('Moneda', 'MXN'),
            'uuid': fiscal_uuid,
            'serie_folio': (data['comprobante'].get('Serie', '') + (('-' if data['comprobante'].get('Serie') and data['comprobante'].get('Folio') else '') + data['comprobante'].get('Folio', ''))),
            'tipo': data['comprobante'].get('TipoDeComprobanteDesc', ''),
            'tipo_comprobante': data['comprobante'].get('TipoDeComprobante', ''),
            'lugar_expedicion': data['comprobante'].get('LugarExpedicion', ''),
            'regimen_fiscal_emisor': data['emisor'].get('RegimenFiscal', ''),
            'subtotal': float(res.get('subtotal', 0)),
            'descuento': float(res.get('descuento', 0)),
            'iva_16': float(res.get('iva_16', 0)),
            'iva_8': float(res.get('iva_8', 0)),
            'iva_0': float(res.get('iva_0', 0)),
            'iva_ret': float(res.get('iva_ret', 0)),
            'isr_ret': float(res.get('isr_ret', 0)),
            'ieps': float(res.get('ieps', 0)),
            'valid': 1 if validation['valid'] else 0,
            'errors': json.dumps(validation['errors']),
            'warnings': json.dumps(validation['warnings']),
        }

        sql = '''
            INSERT OR REPLACE INTO cfdi_records (
                id, filename, emisor_nombre, emisor_rfc, receptor_nombre, receptor_rfc, 
                fecha, fecha_fmt, metodo_pago, metodo_pago_desc, forma_pago, forma_pago_desc, 
                total, total_fmt, moneda, uuid, serie_folio, tipo, tipo_comprobante,
                lugar_expedicion, regimen_fiscal_emisor, subtotal, descuento,
                iva_16, iva_8, iva_0, iva_ret, isr_ret, ieps,
                valid, errors, warnings, xml_content, parsed_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        '''
        params = (
            row['id'], row['filename'], row['emisor_nombre'], row['emisor_rfc'], 
            row['receptor_nombre'], row['receptor_rfc'], row['fecha'], row['fecha_fmt'], 
            row['metodo_pago'], row['metodo_pago_desc'], row['forma_pago'], row['forma_pago_desc'], 
            row['total'], row['total_fmt'], row['moneda'], row['uuid'], row['serie_folio'], 
            row['tipo'], row['tipo_comprobante'], row['lugar_expedicion'], row['regimen_fiscal_emisor'],
            row['subtotal'], row['descuento'], row['iva_16'], row['iva_8'], row['iva_0'], 
            row['iva_ret'], row['isr_ret'], row['ieps'],
            row['valid'], row['errors'], row['warnings'], 
            xml_bytes, json.dumps(data)
        )

        if external_conn:
            external_conn.execute(sql, params)
        else:
            conn = get_db_connection()
            conn.execute(sql, params)
            conn.commit()
            conn.close()
        
        row['errors'] = validation['errors']
        row['warnings'] = validation['warnings']
        row['valid'] = validation['valid']
        return row
    except Exception as e:
        print(f"Error procesando {filename}: {str(e)}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get-records')
def get_records():
    """Obtiene todos los registros guardados."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM cfdi_records ORDER BY fecha DESC')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Decodificar JSON fields
    for r in rows:
        r['errors'] = json.loads(r['errors'])
        r['warnings'] = json.loads(r['warnings'])
        r['valid'] = bool(r['valid'])
        # No enviar el contenido XML pesado en la lista principal
        if 'xml_content' in r: del r['xml_content']
        if 'parsed_json' in r: del r['parsed_json']
    
    return jsonify({'rows': rows})

@app.route('/api/facturas-recibidas')
def api_facturas_recibidas():
    return get_records()

@app.route('/api/facturas-recibidas/<entry_id>')
def api_factura_recibida(entry_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM cfdi_records WHERE id = ?', (entry_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'CFDI no encontrado'}), 404

    data = dict(row)
    data['errors'] = json.loads(data['errors'])
    data['warnings'] = json.loads(data['warnings'])
    data['valid'] = bool(data['valid'])
    data.pop('xml_content', None)
    data.pop('parsed_json', None)
    return jsonify({'row': data})

@app.route('/upload-single', methods=['POST'])
def upload_single():
    if 'xml_file' not in request.files:
        return jsonify({'error': 'No se proporcionó archivo'}), 400
    f = request.files['xml_file']
    if not f.filename.lower().endswith('.xml'):
        return jsonify({'error': 'El archivo debe ser XML'}), 400
    row = parse_and_save(f.read(), f.filename)
    if not row:
        return jsonify({'error': 'Error procesando el archivo'}), 500
    return jsonify({'rows': [row]})

@app.route('/upload-batch', methods=['POST'])
def upload_batch():
    files = request.files.getlist('xml_files')
    if not files:
        return jsonify({'error': 'No se proporcionaron archivos'}), 400
    
    rows = []
    conn = get_db_connection()
    try:
        # Iniciamos transacción masiva
        with conn:
            for f in files:
                if f.filename.lower().endswith('.xml'):
                    # Pasamos la conexión para que no haga commit individual
                    row = parse_and_save(f.read(), f.filename, external_conn=conn)
                    if row: rows.append(row)
                    
    except Exception as e:
        return jsonify({'error': f'Error en procesamiento masivo: {str(e)}'}), 500
    finally:
        conn.close()
        
    return jsonify({'rows': rows, 'total': len(rows)})

@app.route('/upload-folder', methods=['POST'])
def upload_folder():
    data = request.get_json()
    folder_path = data.get('folder_path', '') if data else ''
    if not folder_path or not os.path.isdir(folder_path):
        return jsonify({'error': f'La carpeta no existe o no es accesible: {folder_path}'}), 400
    
    rows = []
    conn = get_db_connection()
    try:
        filenames = [f for f in sorted(os.listdir(folder_path)) if f.lower().endswith('.xml')]
        with conn:
            for fname in filenames:
                fpath = os.path.join(folder_path, fname)
                try:
                    with open(fpath, 'rb') as f:
                        row = parse_and_save(f.read(), fname, external_conn=conn)
                        if row: rows.append(row)
                except Exception as e:
                    print(f"Error leyendo {fname}: {e}")
                    
    except Exception as e:
        return jsonify({'error': f'Error procesando carpeta: {str(e)}'}), 500
    finally:
        conn.close()
        
    return jsonify({'rows': rows, 'total': len(rows)})

@app.route('/preview/<entry_id>')
def preview_entry(entry_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT parsed_json, filename, emisor_nombre, emisor_rfc, receptor_nombre, receptor_rfc, fecha, fecha_fmt, metodo_pago, metodo_pago_desc, forma_pago, forma_pago_desc, total, total_fmt, moneda, uuid, serie_folio, tipo, valid, errors, warnings FROM cfdi_records WHERE id = ?', (entry_id,))
    res = cursor.fetchone()
    conn.close()
    
    if not res:
        return jsonify({'error': 'CFDI no encontrado'}), 404
    
    parsed_json, filename, emisor_nombre, emisor_rfc, receptor_nombre, receptor_rfc, fecha, fecha_fmt, metodo_pago, metodo_pago_desc, forma_pago, forma_pago_desc, total, total_fmt, moneda, uuid, serie_folio, tipo, valid, errors, warnings = res
    data = json.loads(parsed_json)
    
    # Solo generamos el HTML, mucho más rápido que generar el PDF
    html = get_cfdi_html(data)
    
    row = {
        'id': entry_id, 'filename': filename, 'emisor_nombre': emisor_nombre, 'emisor_rfc': emisor_rfc,
        'receptor_nombre': receptor_nombre, 'receptor_rfc': receptor_rfc, 'fecha': fecha, 'fecha_fmt': fecha_fmt,
        'metodo_pago': metodo_pago, 'metodo_pago_desc': metodo_pago_desc, 'forma_pago': forma_pago, 'forma_pago_desc': forma_pago_desc,
        'total': total, 'total_fmt': total_fmt, 'moneda': moneda, 'uuid': uuid, 'serie_folio': serie_folio, 'tipo': tipo,
        'valid': bool(valid), 'errors': json.loads(errors), 'warnings': json.loads(warnings)
    }
    
    return jsonify({
        'html': html,
        'row': row,
    })

@app.route('/download/<entry_id>')
def download_entry(entry_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT parsed_json, serie_folio, uuid FROM cfdi_records WHERE id = ?', (entry_id,))
    res = cursor.fetchone()
    conn.close()
    
    if not res:
        return jsonify({'error': 'CFDI no encontrado'}), 404
    
    parsed_json, serie_folio, uuid_val = res
    data = json.loads(parsed_json)
    
    html = get_cfdi_html(data)
    pdf_bytes = generate_pdf_from_html(html)
    fname = f"CFDI_{serie_folio}_{uuid_val[:8] if uuid_val else entry_id}.pdf"
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf',
                     as_attachment=True, download_name=fname)

@app.route('/clear', methods=['POST'])
def clear_store():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM cfdi_records')
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("   App Facturas Recibidas")
    print("   http://localhost:5050")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5050, debug=True)
