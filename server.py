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
import re
import secrets
import subprocess
from datetime import datetime
from datetime import timedelta
from threading import Lock, Thread
from flask import Flask, render_template, request, send_file, jsonify
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import qrcode
from cfdi_parser import parse_cfdi, validate_cfdi_40

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024  # 256 MB for batch

COMPANIES = {
    'bajanet': {
        'key': 'bajanet',
        'label': 'Bajanet',
    },
    'iamet': {
        'key': 'iamet',
        'label': 'IAMET',
    },
}

DEFAULT_COMPANY = 'bajanet'

def _normalize_rfc(value):
    return (value or '').strip().upper()

COMPANY_RFC_RULES = {
    'bajanet': {'BAJ100903KC6'},
    'iamet': {'IAM170712NL7'},
}

SAT_DOWNLOAD_LOCKS = {key: Lock() for key in COMPANIES}
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, 'data')
SAT_MASTER_KEY_PATH = os.path.join(DATA_DIR, '.sat_master_key')

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response
DB_PATH = os.getenv('DB_PATH', os.path.join(os.path.dirname(__file__), 'cfdi_data.db'))
SQLITE_TIMEOUT_SECONDS = int(os.getenv('SQLITE_TIMEOUT_SECONDS', '30'))
SAT_ACTIVE_STATUSES = ('PROCESSING', 'CONNECTING', 'REQUESTED', 'VERIFYING', 'DOWNLOADING', 'IMPORTING')
SAT_ACTIVE_JOB_SECONDS = int(os.getenv('SAT_ACTIVE_JOB_SECONDS', '180'))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS)
    conn.execute(f'PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}')
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def get_sat_credentials(company_key):
    company_key = normalize_company_key(company_key)
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM sat_credentials WHERE company_key = ?",
            (company_key,),
        ).fetchone()
        if not row:
            return None
        return {
            'company_key': row['company_key'],
            'rfc_receptor': row['rfc_receptor'],
            'cer_filename': row['cer_filename'],
            'key_filename': row['key_filename'],
            'cer_bytes': decrypt_bytes(row['cer_blob']),
            'key_bytes': decrypt_bytes(row['key_blob']),
            'password': decrypt_text(row['encrypted_password']),
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }
    finally:
        conn.close()

def sat_config_status(company_key):
    creds = get_sat_credentials(company_key)
    if not creds:
        return {
            'configured': False,
            'auth_valid': False,
            'auth_error': None,
            'company_key': normalize_company_key(company_key),
            'rfc_receptor': None,
            'has_cer': False,
            'has_key': False,
            'cer_filename': None,
            'key_filename': None,
            'updated_at': None,
        }
    auth_valid = True
    auth_error = None
    try:
        from sat_downloader import validate_sat_bundle

        validate_sat_bundle(creds['cer_bytes'], creds['key_bytes'], creds['password'])
    except Exception as exc:
        auth_valid = False
        auth_error = str(exc)
    return {
        'configured': True,
        'auth_valid': auth_valid,
        'auth_error': auth_error,
        'company_key': creds['company_key'],
        'rfc_receptor': creds['rfc_receptor'],
        'has_cer': True,
        'has_key': True,
        'cer_filename': creds['cer_filename'],
        'key_filename': creds['key_filename'],
        'updated_at': creds['updated_at'],
    }

def save_sat_credentials(company_key, rfc_receptor, cer_file=None, key_file=None, password=''):
    company_key = normalize_company_key(company_key)
    rfc_receptor = _normalize_rfc(rfc_receptor)
    if not rfc_receptor:
        raise ValueError('El RFC receptor es obligatorio.')
    if not re.match(r'^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$', rfc_receptor):
        raise ValueError('El RFC receptor no tiene un formato válido.')
    current = get_sat_credentials(company_key)
    if not password:
        if current:
            password = current['password']
        else:
            raise ValueError('La contraseña de la llave privada es obligatoria.')
    cer_bytes = None
    key_bytes = None
    cer_filename = None
    key_filename = None

    if cer_file is not None:
        cer_bytes = cer_file.read()
        cer_filename = cer_file.filename or 'sat.cer'
    elif current:
        cer_bytes = current['cer_bytes']
        cer_filename = current['cer_filename']

    if key_file is not None:
        key_bytes = key_file.read()
        key_filename = key_file.filename or 'sat.key'
    elif current:
        key_bytes = current['key_bytes']
        key_filename = current['key_filename']

    if not cer_bytes or not key_bytes:
        raise ValueError('Debes cargar los archivos .cer y .key al menos una vez por empresa.')

    from sat_downloader import SatAuthError, SatConfigError, validate_sat_bundle

    try:
        validate_sat_bundle(cer_bytes, key_bytes, password)
    except (SatAuthError, SatConfigError) as exc:
        raise ValueError(str(exc)) from exc

    now_value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO sat_credentials (
                company_key, rfc_receptor, cer_filename, key_filename,
                cer_blob, key_blob, encrypted_password, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(company_key) DO UPDATE SET
                rfc_receptor=excluded.rfc_receptor,
                cer_filename=excluded.cer_filename,
                key_filename=excluded.key_filename,
                cer_blob=excluded.cer_blob,
                key_blob=excluded.key_blob,
                encrypted_password=excluded.encrypted_password,
                updated_at=excluded.updated_at
            """,
            (
                company_key,
                rfc_receptor,
                cer_filename,
                key_filename,
                encrypt_bytes(cer_bytes),
                encrypt_bytes(key_bytes),
                encrypt_text(password),
                current['created_at'] if current else now_value,
                now_value,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return sat_config_status(company_key)

def get_sat_jobs(company_key, limit=20):
    company_key = normalize_company_key(company_key)
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, company_key, request_type, date_from, date_to, status,
                   request_id, packages_count, xmls_imported, cfdis_count,
                   progress_message, last_checked_at, error_message,
                   created_at, completed_at
            FROM sat_download_jobs
            WHERE company_key = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (company_key, int(limit)),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_sat_job(job_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT id, company_key, request_type, date_from, date_to, status,
                   request_id, packages_count, xmls_imported, cfdis_count,
                   progress_message, last_checked_at, error_message,
                   created_at, completed_at
            FROM sat_download_jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_recent_active_sat_job(company_key, request_type, date_from, date_to):
    cutoff = (datetime.now() - timedelta(seconds=SAT_ACTIVE_JOB_SECONDS)).strftime('%Y-%m-%d %H:%M:%S')
    placeholders = ','.join('?' for _ in SAT_ACTIVE_STATUSES)
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            f"""
            SELECT id, company_key, request_type, date_from, date_to, status,
                   request_id, packages_count, xmls_imported, cfdis_count,
                   progress_message, last_checked_at, error_message,
                   created_at, completed_at
            FROM sat_download_jobs
            WHERE company_key = ?
              AND request_type = ?
              AND date_from = ?
              AND date_to = ?
              AND status IN ({placeholders})
              AND COALESCE(last_checked_at, created_at) >= ?
            ORDER BY COALESCE(last_checked_at, created_at) DESC
            LIMIT 1
            """,
            (company_key, request_type, date_from, date_to, *SAT_ACTIVE_STATUSES, cutoff),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def get_sat_master_secret():
    ensure_data_dir()
    if os.path.exists(SAT_MASTER_KEY_PATH):
        with open(SAT_MASTER_KEY_PATH, 'r', encoding='utf-8') as fh:
            secret = fh.read().strip()
            if secret:
                return secret
    secret = secrets.token_urlsafe(48)
    with open(SAT_MASTER_KEY_PATH, 'w', encoding='utf-8') as fh:
        fh.write(secret)
    try:
        os.chmod(SAT_MASTER_KEY_PATH, 0o600)
    except Exception:
        pass
    return secret

def _openssl_crypt(payload, decrypt=False):
    secret = get_sat_master_secret()
    cmd = [
        'openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000',
        '-salt', '-a', '-A', '-pass', f'pass:{secret}',
    ]
    if decrypt:
        cmd.insert(2, '-d')
    proc = subprocess.run(cmd, input=payload, capture_output=True, check=False)
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='ignore').strip()
        raise RuntimeError(stderr or 'Error de cifrado local.')
    return proc.stdout

def encrypt_bytes(data):
    return _openssl_crypt(data or b'')

def decrypt_bytes(data):
    if not data:
        return b''
    return _openssl_crypt(data, decrypt=True)

def encrypt_text(text):
    return encrypt_bytes((text or '').encode('utf-8')).decode('utf-8')

def decrypt_text(text):
    return decrypt_bytes((text or '').encode('utf-8')).decode('utf-8')

def normalize_company_key(value):
    value = (value or DEFAULT_COMPANY).strip().lower()
    return value if value in COMPANIES else DEFAULT_COMPANY

def get_company_meta(company_key=None):
    company_key = normalize_company_key(company_key)
    return COMPANIES[company_key]

def get_request_company():
    company = request.args.get('company') or request.form.get('company')
    if not company and request.is_json:
        payload = request.get_json(silent=True) or {}
        company = payload.get('company')
    return normalize_company_key(company)

def scoped_entry_id(company_key, entry_source_id):
    return f"{company_key.upper()}_{entry_source_id}"

def detect_company_from_rfcs(emisor_rfc, receptor_rfc, fallback_company=DEFAULT_COMPANY):
    """
    Detecta la empresa por RFC.
    Prioriza receptor porque en facturas recibidas representa la empresa destino.
    """
    emisor_rfc = _normalize_rfc(emisor_rfc)
    receptor_rfc = _normalize_rfc(receptor_rfc)

    def match_company(rfc):
        if not rfc:
            return None
        matches = [key for key, rfcs in COMPANY_RFC_RULES.items() if rfc in rfcs]
        return matches[0] if len(matches) == 1 else None

    receptor_match = match_company(receptor_rfc)
    emisor_match = match_company(emisor_rfc)

    if receptor_match and emisor_match and receptor_match != emisor_match:
        return receptor_match
    return receptor_match or emisor_match or normalize_company_key(fallback_company)

def cleanup_duplicate_records(conn):
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM cfdi_records
        WHERE rowid NOT IN (
            SELECT MAX(rowid)
            FROM cfdi_records
            WHERE uuid IS NOT NULL AND uuid != ''
            GROUP BY company_key, uuid
        )
        AND uuid IS NOT NULL AND uuid != ''
    ''')

def ensure_cfdi_uuid_index(conn):
    conn.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cfdi_company_uuid
        ON cfdi_records (company_key, uuid)
        WHERE uuid IS NOT NULL AND uuid != ''
    ''')

def mark_interrupted_sat_jobs(conn):
    placeholders = ','.join('?' for _ in SAT_ACTIVE_STATUSES)
    now_value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        f'''
        UPDATE sat_download_jobs
        SET status = 'ERROR',
            error_message = 'Proceso local interrumpido. Vuelve a iniciar la descarga para reanudar con el SAT.',
            progress_message = 'Proceso local interrumpido. Vuelve a iniciar la descarga para reanudar con el SAT.',
            completed_at = ?,
            last_checked_at = ?
        WHERE status IN ({placeholders})
        ''',
        (now_value, now_value, *SAT_ACTIVE_STATUSES),
    )

def repair_reconciliation_results_schema(conn):
    fks = conn.execute("PRAGMA foreign_key_list(reconciliation_results)").fetchall()
    has_invalid_cfdi_fk = any(
        row[2] == 'cfdi_records' and row[3] == 'invoice_uuid' and row[4] == 'uuid'
        for row in fks
    )
    if not has_invalid_cfdi_fk:
        return

    conn.execute("ALTER TABLE reconciliation_results RENAME TO reconciliation_results_old")
    conn.execute('''
        CREATE TABLE reconciliation_results (
            id TEXT PRIMARY KEY,
            invoice_uuid TEXT,
            purchase_order_id TEXT,
            receipt_id TEXT,
            score REAL,
            status TEXT,
            diff_amount REAL,
            diff_qty REAL,
            diff_currency TEXT,
            details TEXT,
            created_at TEXT,
            FOREIGN KEY(purchase_order_id) REFERENCES purchase_orders(id) ON DELETE SET NULL,
            FOREIGN KEY(receipt_id) REFERENCES receipts(id) ON DELETE SET NULL
        )
    ''')
    conn.execute('''
        INSERT INTO reconciliation_results (
            id, invoice_uuid, purchase_order_id, receipt_id, score, status,
            diff_amount, diff_qty, diff_currency, details, created_at
        )
        SELECT
            id, invoice_uuid, purchase_order_id, receipt_id, score, status,
            diff_amount, diff_qty, diff_currency, details, created_at
        FROM reconciliation_results_old
    ''')
    conn.execute("DROP TABLE reconciliation_results_old")

def init_db():
    """Inicializa la base de datos SQLite y realiza limpieza de duplicados."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    ensure_data_dir()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode = WAL')
    cursor.execute('PRAGMA synchronous = NORMAL')

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
            company_key TEXT NOT NULL DEFAULT 'bajanet',
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sat_credentials (
            company_key TEXT PRIMARY KEY,
            rfc_receptor TEXT NOT NULL,
            cer_filename TEXT NOT NULL,
            key_filename TEXT NOT NULL,
            cer_blob BLOB NOT NULL,
            key_blob BLOB NOT NULL,
            encrypted_password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sat_download_jobs (
            id TEXT PRIMARY KEY,
            company_key TEXT NOT NULL,
            request_type TEXT NOT NULL,
            date_from TEXT NOT NULL,
            date_to TEXT NOT NULL,
            status TEXT NOT NULL,
            request_id TEXT,
            packages_count INTEGER DEFAULT 0,
            xmls_imported INTEGER DEFAULT 0,
            cfdis_count INTEGER DEFAULT 0,
            progress_message TEXT,
            last_checked_at TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    ''')

    cursor.execute("PRAGMA table_info(cfdi_records)")
    columns = {row[1] for row in cursor.fetchall()}
    if 'company_key' not in columns:
        cursor.execute("ALTER TABLE cfdi_records ADD COLUMN company_key TEXT NOT NULL DEFAULT 'bajanet'")

    job_columns = {row[1] for row in conn.execute("PRAGMA table_info(sat_download_jobs)").fetchall()}
    for column, ddl in {
        "company_key": "ALTER TABLE sat_download_jobs ADD COLUMN company_key TEXT NOT NULL DEFAULT 'bajanet'",
        "packages_count": "ALTER TABLE sat_download_jobs ADD COLUMN packages_count INTEGER DEFAULT 0",
        "xmls_imported": "ALTER TABLE sat_download_jobs ADD COLUMN xmls_imported INTEGER DEFAULT 0",
        "cfdis_count": "ALTER TABLE sat_download_jobs ADD COLUMN cfdis_count INTEGER DEFAULT 0",
        "progress_message": "ALTER TABLE sat_download_jobs ADD COLUMN progress_message TEXT",
        "last_checked_at": "ALTER TABLE sat_download_jobs ADD COLUMN last_checked_at TEXT",
        "error_message": "ALTER TABLE sat_download_jobs ADD COLUMN error_message TEXT",
        "completed_at": "ALTER TABLE sat_download_jobs ADD COLUMN completed_at TEXT",
    }.items():
        if column not in job_columns:
            conn.execute(ddl)

    try:
        cleanup_duplicate_records(conn)
    except Exception:
        pass
    try:
        ensure_cfdi_uuid_index(conn)
    except Exception:
        pass
    try:
        repair_reconciliation_results_schema(conn)
    except Exception as exc:
        print(f"No fue posible reparar reconciliation_results: {exc}")
    try:
        mark_interrupted_sat_jobs(conn)
    except Exception as exc:
        print(f"No fue posible cerrar jobs SAT interrumpidos: {exc}")
        
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

def parse_and_save(xml_bytes, filename, company_key=DEFAULT_COMPANY, external_conn=None):
    """
    Parsea un XML y lo guarda. 
    Si se pasa external_conn, no hace commit ni cierra para permitir transacciones masivas.
    """
    try:
        import hashlib
        data = parse_cfdi(xml_bytes)
        validation = validate_cfdi_40(data)
        res = data.get('resumen_fiscal', {})
        company_key = detect_company_from_rfcs(
            data['emisor'].get('Rfc', ''),
            data['receptor'].get('Rfc', ''),
            fallback_company=company_key,
        )
        
        fiscal_uuid = data['timbre'].get('UUID', '').upper()
        if fiscal_uuid:
            entry_source_id = fiscal_uuid
        else:
            # Si no hay UUID, usamos un hash del contenido para evitar duplicados del mismo archivo
            entry_source_id = "HASH_" + hashlib.md5(xml_bytes).hexdigest()
        entry_id = scoped_entry_id(company_key, entry_source_id)
        
        row = {
            'id': entry_id,
            'company_key': company_key,
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
                valid, errors, warnings, company_key, xml_content, parsed_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        '''
        params = (
            row['id'], row['filename'], row['emisor_nombre'], row['emisor_rfc'], 
            row['receptor_nombre'], row['receptor_rfc'], row['fecha'], row['fecha_fmt'], 
            row['metodo_pago'], row['metodo_pago_desc'], row['forma_pago'], row['forma_pago_desc'], 
            row['total'], row['total_fmt'], row['moneda'], row['uuid'], row['serie_folio'], 
            row['tipo'], row['tipo_comprobante'], row['lugar_expedicion'], row['regimen_fiscal_emisor'],
            row['subtotal'], row['descuento'], row['iva_16'], row['iva_8'], row['iva_0'], 
            row['iva_ret'], row['isr_ret'], row['ieps'],
            row['valid'], row['errors'], row['warnings'], row['company_key'],
            xml_bytes, json.dumps(data)
        )

        if external_conn:
            external_conn.execute(sql, params)
        else:
            conn = get_db_connection()
            conn.execute(sql, params)
            ensure_cfdi_uuid_index(conn)
            cleanup_duplicate_records(conn)
            conn.commit()
            conn.close()
        
        row['errors'] = validation['errors']
        row['warnings'] = validation['warnings']
        row['valid'] = validation['valid']
        return row
    except Exception as e:
        print(f"Error procesando {filename}: {str(e)}")
        return None

def start_sat_download_job(company_key, date_from, date_to, request_type, resumable_request_id=None):
    company_key = normalize_company_key(company_key)
    lock = SAT_DOWNLOAD_LOCKS[company_key]
    if not lock.acquire(blocking=False):
        raise RuntimeError(f"Ya hay una descarga SAT en proceso para {COMPANIES[company_key]['label']}.")

    job_id = str(uuid.uuid4())
    now_value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO sat_download_jobs
                (id, company_key, request_type, date_from, date_to, status, request_id, progress_message, created_at)
            VALUES (?, ?, ?, ?, ?, 'PROCESSING', ?, ?, ?)
            """,
            (
                job_id,
                company_key,
                request_type,
                date_from,
                date_to,
                resumable_request_id,
                'Reanudando solicitud SAT existente.' if resumable_request_id else 'Preparando solicitud SAT.',
                now_value,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    def update_job(**fields):
        if not fields:
            return
        fields['last_checked_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        assignments = ', '.join(f'{key}=?' for key in fields)
        values = list(fields.values()) + [job_id]
        conn = get_db_connection()
        try:
            conn.execute(f'UPDATE sat_download_jobs SET {assignments} WHERE id=?', values)
            conn.commit()
        finally:
            conn.close()

    def progress(event):
        stage = event.get('stage')
        if stage == 'connecting':
            update_job(status='CONNECTING', progress_message=event.get('message') or 'Conectando con SAT.')
        elif stage == 'requested':
            update_job(
                status='REQUESTED',
                request_id=event.get('request_id'),
                progress_message=event.get('message') or 'Solicitud aceptada por SAT.',
            )
        elif stage == 'verify':
            packages_count = int(event.get('packages_count') or 0)
            cfdis_count = int(event.get('cfdis_count') or 0)
            sat_state = ' / '.join(str(value) for value in (event.get('status_code'), event.get('status')) if value)
            if str(event.get('status_code') or '') == '2':
                message = f"SAT aceptó la solicitud. Esperando paquetes. Intento {event.get('attempt', '-')}. CFDIs: {cfdis_count}."
            else:
                message = f"Verificando SAT. Intento {event.get('attempt', '-')}. Estado: {sat_state or 'pendiente'}. CFDIs: {cfdis_count}."
            update_job(
                status='VERIFYING',
                packages_count=packages_count,
                cfdis_count=cfdis_count,
                progress_message=message,
            )
        elif stage == 'verified':
            update_job(
                status='DOWNLOADING' if int(event.get('packages_count') or 0) else 'VERIFYING',
                packages_count=int(event.get('packages_count') or 0),
                cfdis_count=int(event.get('cfdis_count') or 0),
                progress_message=event.get('message') or 'Solicitud verificada por SAT.',
            )
        elif stage == 'downloading':
            update_job(status='DOWNLOADING', progress_message=event.get('message') or 'Descargando paquete SAT.')
        elif stage == 'package_done':
            update_job(progress_message=event.get('message') or 'Paquete SAT procesado.')

    def worker():
        try:
            creds = get_sat_credentials(company_key)
            if not creds:
                raise RuntimeError(
                    f"No hay credenciales SAT configuradas para {COMPANIES[company_key]['label']}."
                )
            from sat_downloader import SatConfigError, SatDownloader

            downloader = SatDownloader(
                creds['rfc_receptor'],
                creds['cer_bytes'],
                creds['key_bytes'],
                creds['password'],
            )
            result = downloader.execute_full_flow(
                date_from,
                date_to,
                request_type,
                progress_callback=progress,
                existing_request_id=resumable_request_id,
            )
            if result['status'] == 'error':
                update_job(
                    status='ERROR',
                    request_id=result.get('request_id'),
                    error_message=result.get('error'),
                    progress_message=result.get('error') or 'Error en descarga SAT.',
                    completed_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                )
                return

            total_xmls = len(result.get('xmls', []))
            imported_count = 0
            error_count = 0
            if total_xmls > 0:
                update_job(status='IMPORTING', progress_message=f'Importando {total_xmls} XMLs descargados.')

            conn_local = get_db_connection()
            try:
                for idx, xml_item in enumerate(result.get('xmls', []), 1):
                    try:
                        row = parse_and_save(
                            xml_item['content'],
                            xml_item['filename'],
                            company_key=company_key,
                            external_conn=conn_local,
                        )
                        if row:
                            imported_count += 1
                        else:
                            error_count += 1
                    except Exception:
                        error_count += 1
                    if idx % 5 == 0 or idx == total_xmls:
                        conn_local.commit()
                        pct = (idx / total_xmls) * 100 if total_xmls else 100
                        update_job(
                            xmls_imported=imported_count,
                            progress_message=f'Importando {idx}/{total_xmls} ({pct:.0f}%).',
                        )
                cleanup_duplicate_records(conn_local)
                conn_local.commit()
            except Exception:
                conn_local.rollback()
                raise
            finally:
                conn_local.close()

            final_status = 'COMPLETED' if result['status'] != 'no_data' else 'NO_DATA'
            final_message = (
                f'Descarga SAT completada. Facturas importadas: {imported_count}.'
                if final_status == 'COMPLETED'
                else 'El SAT no encontró facturas para el rango solicitado.'
            )
            final_error_message = None
            if int(result.get('packages_count') or 0) > 0 and imported_count == 0 and (result.get('download_errors') or error_count):
                final_status = 'ERROR'
                final_error_message = '; '.join(
                    f"{item.get('package_id')}: {item.get('error')}" for item in result.get('download_errors', [])
                )[:2000] or 'No fue posible importar los XML descargados.'
                final_message = final_error_message
            elif error_count > 0:
                final_message = f"{final_message} XMLs con error: {error_count}."

            update_job(
                status=final_status,
                request_id=result.get('request_id'),
                packages_count=result.get('packages_count', 0),
                xmls_imported=imported_count,
                progress_message=final_message,
                error_message=final_error_message,
                completed_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            )
        except Exception as exc:
            update_job(
                status='ERROR',
                error_message=str(exc),
                progress_message=str(exc),
                completed_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            )
        finally:
            lock.release()

    Thread(target=worker, daemon=True).start()
    return job_id

@app.route('/')
def index():
    company_key = get_request_company()
    return render_template('index.html', selected_company=company_key, company=COMPANIES[company_key], companies=COMPANIES)

@app.route('/empresa/<company_key>')
def index_company(company_key):
    company_key = normalize_company_key(company_key)
    return render_template('index.html', selected_company=company_key, company=COMPANIES[company_key], companies=COMPANIES)

@app.route('/get-records')
def get_records():
    """Obtiene todos los registros guardados."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    company_key = get_request_company()
    cursor.execute('SELECT * FROM cfdi_records WHERE COALESCE(company_key, "bajanet") = ? ORDER BY fecha DESC', (company_key,))
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

@app.route('/api/sat/config', methods=['GET'])
def api_sat_config_get():
    company_key = get_request_company()
    return jsonify(sat_config_status(company_key))

@app.route('/api/sat/config', methods=['POST'])
def api_sat_config_post():
    company_key = normalize_company_key(request.form.get('company') or request.args.get('company'))
    rfc_receptor = (request.form.get('rfc_receptor') or '').strip().upper()
    password = request.form.get('password') or ''
    cer_file = request.files.get('cer_file')
    key_file = request.files.get('key_file')

    if cer_file and not cer_file.filename.lower().endswith('.cer'):
        return jsonify({'error': 'El archivo CER debe terminar en .cer'}), 400
    if key_file and not key_file.filename.lower().endswith('.key'):
        return jsonify({'error': 'El archivo KEY debe terminar en .key'}), 400

    try:
        status = save_sat_credentials(company_key, rfc_receptor, cer_file=cer_file, key_file=key_file, password=password)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'No fue posible guardar las credenciales SAT: {exc}'}), 500
    return jsonify({'ok': True, 'config': status})

@app.route('/api/sat/jobs', methods=['GET'])
def api_sat_jobs():
    company_key = get_request_company()
    limit = request.args.get('limit', '20')
    try:
        limit = max(1, min(100, int(limit)))
    except ValueError:
        limit = 20
    return jsonify({'rows': get_sat_jobs(company_key, limit=limit)})

@app.route('/api/sat/jobs/<job_id>', methods=['GET'])
def api_sat_job(job_id):
    job = get_sat_job(job_id)
    if not job:
        return jsonify({'error': 'Trabajo SAT no encontrado'}), 404
    return jsonify({'row': job})

@app.route('/api/sat/download', methods=['POST'])
def api_sat_download():
    company_key = get_request_company()
    data = request.get_json(silent=True) or {}
    date_from = (data.get('date_from') or '').strip()
    date_to = (data.get('date_to') or '').strip()
    request_type = (data.get('request_type') or 'received').strip().lower()

    if not date_from or not date_to:
        return jsonify({'error': 'Se requieren date_from y date_to en formato YYYY-MM-DD'}), 400
    if request_type not in ('received', 'issued'):
        return jsonify({'error': "request_type debe ser 'received' o 'issued'"}), 400

    try:
        date_from_dt = datetime.strptime(date_from, '%Y-%m-%d').date()
        date_to_dt = datetime.strptime(date_to, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Formato de fecha inválido. Usar YYYY-MM-DD'}), 400

    today_dt = datetime.now().date()
    if date_to_dt > today_dt:
        date_to_dt = today_dt
        date_to = date_to_dt.isoformat()
    if date_from_dt > date_to_dt:
        return jsonify({'error': 'La fecha inicial no puede ser posterior a la fecha final'}), 400

    if not get_sat_credentials(company_key):
        return jsonify({
            'error': f'No hay credenciales SAT configuradas para {COMPANIES[company_key]["label"]}.',
        }), 400
    config_status = sat_config_status(company_key)
    if not config_status.get('auth_valid', False):
        return jsonify({
            'error': config_status.get('auth_error') or 'La FIEL configurada no pudo validarse.',
        }), 400

    active_job = get_recent_active_sat_job(company_key, request_type, date_from, date_to)
    if active_job:
        return jsonify({
            'ok': True,
            'job_id': active_job['id'],
            'status': active_job['status'],
            'message': active_job.get('progress_message') or 'La descarga SAT ya está en proceso.',
            'reused': True,
        }), 202

    resumable_request_id = None
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        resumable_job = conn.execute(
            """
            SELECT request_id
            FROM sat_download_jobs
            WHERE company_key = ?
              AND request_type = ?
              AND date_from = ?
              AND date_to = ?
              AND request_id IS NOT NULL
              AND TRIM(request_id) <> ''
              AND status IN ('REQUESTED', 'VERIFYING')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (company_key, request_type, date_from, date_to),
        ).fetchone()
        if resumable_job:
            resumable_request_id = str(resumable_job['request_id'] or '').strip() or None
    finally:
        conn.close()

    try:
        job_id = start_sat_download_job(company_key, date_from, date_to, request_type, resumable_request_id)
    except RuntimeError as exc:
        return jsonify({'error': str(exc), 'busy': True}), 409
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({
        'ok': True,
        'job_id': job_id,
        'status': 'PROCESSING',
        'message': 'Descarga SAT encolada. El proceso continúa en segundo plano.',
    }), 202

@app.route('/upload-single', methods=['POST'])
def upload_single():
    if 'xml_file' not in request.files:
        return jsonify({'error': 'No se proporcionó archivo'}), 400
    f = request.files['xml_file']
    if not f.filename.lower().endswith('.xml'):
        return jsonify({'error': 'El archivo debe ser XML'}), 400
    company_key = normalize_company_key(request.form.get('company') or request.args.get('company'))
    row = parse_and_save(f.read(), f.filename, company_key=company_key)
    if not row:
        return jsonify({'error': 'Error procesando el archivo'}), 500
    return jsonify({'rows': [row]})

@app.route('/upload-batch', methods=['POST'])
def upload_batch():
    files = request.files.getlist('xml_files')
    if not files:
        return jsonify({'error': 'No se proporcionaron archivos'}), 400
    company_key = normalize_company_key(request.form.get('company') or request.args.get('company'))
    
    rows = []
    conn = get_db_connection()
    try:
        # Iniciamos transacción masiva
        with conn:
            for f in files:
                if f.filename.lower().endswith('.xml'):
                    # Pasamos la conexión para que no haga commit individual
                    row = parse_and_save(f.read(), f.filename, company_key=company_key, external_conn=conn)
                    if row: rows.append(row)
            cleanup_duplicate_records(conn)
                    
    except Exception as e:
        return jsonify({'error': f'Error en procesamiento masivo: {str(e)}'}), 500
    finally:
        conn.close()
        
    return jsonify({'rows': rows, 'total': len(rows)})

@app.route('/upload-folder', methods=['POST'])
def upload_folder():
    data = request.get_json()
    folder_path = data.get('folder_path', '') if data else ''
    company_key = normalize_company_key(data.get('company') if data else None)
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
                        row = parse_and_save(f.read(), fname, company_key=company_key, external_conn=conn)
                        if row: rows.append(row)
                except Exception as e:
                    print(f"Error leyendo {fname}: {e}")
            cleanup_duplicate_records(conn)
                    
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

@app.route('/download-xml/<entry_id>')
def download_xml_entry(entry_id):
    company_key = get_request_company()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT xml_content, filename, serie_folio, uuid
        FROM cfdi_records
        WHERE id = ? AND COALESCE(company_key, "bajanet") = ?
        ''',
        (entry_id, company_key),
    )
    res = cursor.fetchone()
    conn.close()

    if not res:
        return jsonify({'error': 'CFDI no encontrado'}), 404

    xml_content, filename, serie_folio, uuid_val = res
    if not xml_content:
        return jsonify({'error': 'XML no disponible'}), 404

    base_name = filename if filename and filename.lower().endswith('.xml') else f"CFDI_{serie_folio or uuid_val or entry_id}.xml"
    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', base_name).strip('._') or 'cfdi.xml'
    if not safe_name.lower().endswith('.xml'):
        safe_name += '.xml'

    return send_file(
        io.BytesIO(xml_content),
        mimetype='application/xml',
        as_attachment=True,
        download_name=safe_name,
    )

@app.route('/clear', methods=['POST'])
def clear_store():
    company_key = get_request_company()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM cfdi_records WHERE company_key = ?', (company_key,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', '0') == '1'
    print("\n" + "=" * 60)
    print("   App Facturas Recibidas")
    print("   http://localhost:5050")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5050, debug=debug_mode, use_reloader=debug_mode)
