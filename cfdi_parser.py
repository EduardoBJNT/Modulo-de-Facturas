"""
CFDI 4.0 XML Parser — Extrae todos los nodos fiscales requeridos por el SAT.
Usa lxml para manejar namespaces XML correctamente.
Maneja decimales con Decimal (punto fijo) para evitar errores de centavo.
"""

from lxml import etree
from decimal import Decimal, ROUND_HALF_UP
import re

# Namespaces oficiales del SAT para CFDI 4.0
NS = {
    'cfdi': 'http://www.sat.gob.mx/cfd/4',
    'tfd': 'http://www.sat.gob.mx/TimbreFiscalDigital',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

# Catálogos SAT más usados
CATALOGO_REGIMEN_FISCAL = {
    '601': 'General de Ley Personas Morales',
    '603': 'Personas Morales con Fines no Lucrativos',
    '605': 'Sueldos y Salarios e Ingresos Asimilados a Salarios',
    '606': 'Arrendamiento',
    '607': 'Régimen de Enajenación o Adquisición de Bienes',
    '608': 'Demás ingresos',
    '610': 'Residentes en el Extranjero sin Establecimiento Permanente en México',
    '611': 'Ingresos por Dividendos (socios y accionistas)',
    '612': 'Personas Físicas con Actividades Empresariales y Profesionales',
    '614': 'Ingresos por intereses',
    '615': 'Régimen de los ingresos por obtención de premios',
    '616': 'Sin obligaciones fiscales',
    '620': 'Sociedades Cooperativas de Producción que optan por diferir sus ingresos',
    '621': 'Incorporación Fiscal',
    '622': 'Actividades Agrícolas, Ganaderas, Silvícolas y Pesqueras',
    '623': 'Opcional para Grupos de Sociedades',
    '624': 'Coordinados',
    '625': 'Régimen de las Actividades Empresariales con ingresos a través de Plataformas Tecnológicas',
    '626': 'Régimen Simplificado de Confianza',
}

CATALOGO_USO_CFDI = {
    'G01': 'Adquisición de mercancías',
    'G02': 'Devoluciones, descuentos o bonificaciones',
    'G03': 'Gastos en general',
    'I01': 'Construcciones',
    'I02': 'Mobiliario y equipo de oficina por inversiones',
    'I03': 'Equipo de transporte',
    'I04': 'Equipo de cómputo y accesorios',
    'I05': 'Dados, troqueles, moldes, matrices y herramental',
    'I06': 'Comunicaciones telefónicas',
    'I07': 'Comunicaciones satelitales',
    'I08': 'Otra maquinaria y equipo',
    'D01': 'Honorarios médicos, dentales y gastos hospitalarios',
    'D02': 'Gastos médicos por incapacidad o discapacidad',
    'D03': 'Gastos funerales',
    'D04': 'Donativos',
    'D05': 'Intereses reales efectivamente pagados por créditos hipotecarios (casa habitación)',
    'D06': 'Aportaciones voluntarias al SAR',
    'D07': 'Primas por seguros de gastos médicos',
    'D08': 'Gastos de transportación escolar obligatoria',
    'D09': 'Depósitos en cuentas para el ahorro, primas que tengan como base planes de pensiones',
    'D10': 'Pagos por servicios educativos (colegiaturas)',
    'S01': 'Sin efectos fiscales',
    'CP01': 'Pagos',
    'CN01': 'Nómina',
}

CATALOGO_FORMA_PAGO = {
    '01': 'Efectivo',
    '02': 'Cheque nominativo',
    '03': 'Transferencia electrónica de fondos',
    '04': 'Tarjeta de crédito',
    '05': 'Monedero electrónico',
    '06': 'Dinero electrónico',
    '08': 'Vales de despensa',
    '12': 'Dación en pago',
    '13': 'Pago por subrogación',
    '14': 'Pago por consignación',
    '15': 'Condonación',
    '17': 'Compensación',
    '23': 'Novación',
    '24': 'Confusión',
    '25': 'Remisión de deuda',
    '26': 'Prescripción o caducidad',
    '27': 'A satisfacción del acreedor',
    '28': 'Tarjeta de débito',
    '29': 'Tarjeta de servicios',
    '30': 'Aplicación de anticipos',
    '31': 'Intermediario pagos',
    '99': 'Por definir',
}

CATALOGO_METODO_PAGO = {
    'PUE': 'Pago en una sola exhibición',
    'PPD': 'Pago en parcialidades o diferido',
}

CATALOGO_TIPO_COMPROBANTE = {
    'I': 'Ingreso',
    'E': 'Egreso',
    'T': 'Traslado',
    'N': 'Nómina',
    'P': 'Pago',
}

CATALOGO_IMPUESTO = {
    '001': 'ISR',
    '002': 'IVA',
    '003': 'IEPS',
}

CATALOGO_MONEDA = {
    'MXN': 'Peso Mexicano',
    'USD': 'Dólar Americano',
    'EUR': 'Euro',
}


def _attr(node, name, default=''):
    """Extrae un atributo de un nodo XML de forma segura."""
    if node is None:
        return default
    return node.get(name, default)


def _decimal(value, decimals=2):
    """Convierte un valor a Decimal con precisión fija."""
    if not value:
        return Decimal('0.00')
    try:
        d = Decimal(str(value))
        quant = Decimal('0.' + '0' * decimals)
        return d.quantize(quant, rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal('0.00')


def _format_money(value, decimals=2):
    """Formatea un Decimal como string monetario."""
    d = _decimal(value, decimals)
    return f"${d:,.{decimals}f}"


def parse_cfdi(xml_content):
    """
    Parsea un XML de CFDI 4.0 y extrae toda la información requerida
    para generar la representación impresa conforme al SAT.
    
    Returns: dict con todos los datos del CFDI
    """
    # Parse XML
    if isinstance(xml_content, str):
        xml_content = xml_content.encode('utf-8')
    
    # Remove BOM if present
    if xml_content.startswith(b'\xef\xbb\xbf'):
        xml_content = xml_content[3:]
    
    root = etree.fromstring(xml_content)
    
    # --- COMPROBANTE (nodo raíz) ---
    comprobante = {
        'Version': _attr(root, 'Version'),
        'Serie': _attr(root, 'Serie'),
        'Folio': _attr(root, 'Folio'),
        'Fecha': _attr(root, 'Fecha'),
        'Sello': _attr(root, 'Sello'),
        'FormaPago': _attr(root, 'FormaPago'),
        'FormaPagoDesc': CATALOGO_FORMA_PAGO.get(_attr(root, 'FormaPago'), ''),
        'NoCertificado': _attr(root, 'NoCertificado'),
        'Certificado': _attr(root, 'Certificado'),
        'CondicionesDePago': _attr(root, 'CondicionesDePago'),
        'SubTotal': _attr(root, 'SubTotal'),
        'Descuento': _attr(root, 'Descuento', '0.00'),
        'Moneda': _attr(root, 'Moneda'),
        'MonedaDesc': CATALOGO_MONEDA.get(_attr(root, 'Moneda'), _attr(root, 'Moneda')),
        'TipoCambio': _attr(root, 'TipoCambio', '1'),
        'Total': _attr(root, 'Total'),
        'TipoDeComprobante': _attr(root, 'TipoDeComprobante'),
        'TipoDeComprobanteDesc': CATALOGO_TIPO_COMPROBANTE.get(
            _attr(root, 'TipoDeComprobante'), ''
        ),
        'Exportacion': _attr(root, 'Exportacion'),
        'MetodoPago': _attr(root, 'MetodoPago'),
        'MetodoPagoDesc': CATALOGO_METODO_PAGO.get(_attr(root, 'MetodoPago'), ''),
        'LugarExpedicion': _attr(root, 'LugarExpedicion'),
    }
    
    # Formateo monetario
    comprobante['SubTotalFmt'] = _format_money(comprobante['SubTotal'])
    comprobante['DescuentoFmt'] = _format_money(comprobante['Descuento'])
    comprobante['TotalFmt'] = _format_money(comprobante['Total'])
    comprobante['TotalLetras'] = _numero_a_letras(comprobante['Total'], comprobante['Moneda'])
    
    # Formato de fecha legible
    fecha_raw = comprobante['Fecha']
    if fecha_raw:
        comprobante['FechaFmt'] = fecha_raw.replace('T', ' ')
    
    # --- EMISOR ---
    emisor_node = root.find('cfdi:Emisor', NS)
    emisor = {
        'Rfc': _attr(emisor_node, 'Rfc'),
        'Nombre': _attr(emisor_node, 'Nombre'),
        'RegimenFiscal': _attr(emisor_node, 'RegimenFiscal'),
        'RegimenFiscalDesc': CATALOGO_REGIMEN_FISCAL.get(
            _attr(emisor_node, 'RegimenFiscal'), ''
        ),
    }
    
    # --- RECEPTOR ---
    receptor_node = root.find('cfdi:Receptor', NS)
    receptor = {
        'Rfc': _attr(receptor_node, 'Rfc'),
        'Nombre': _attr(receptor_node, 'Nombre'),
        'DomicilioFiscalReceptor': _attr(receptor_node, 'DomicilioFiscalReceptor'),
        'RegimenFiscalReceptor': _attr(receptor_node, 'RegimenFiscalReceptor'),
        'RegimenFiscalReceptorDesc': CATALOGO_REGIMEN_FISCAL.get(
            _attr(receptor_node, 'RegimenFiscalReceptor'), ''
        ),
        'UsoCFDI': _attr(receptor_node, 'UsoCFDI'),
        'UsoCFDIDesc': CATALOGO_USO_CFDI.get(_attr(receptor_node, 'UsoCFDI'), ''),
    }
    
    # --- CONCEPTOS ---
    conceptos = []
    conceptos_node = root.find('cfdi:Conceptos', NS)
    if conceptos_node is not None:
        for i, concepto in enumerate(conceptos_node.findall('cfdi:Concepto', NS), 1):
            c = {
                'No': i,
                'ClaveProdServ': _attr(concepto, 'ClaveProdServ'),
                'NoIdentificacion': _attr(concepto, 'NoIdentificacion'),
                'Cantidad': _attr(concepto, 'Cantidad'),
                'ClaveUnidad': _attr(concepto, 'ClaveUnidad'),
                'Unidad': _attr(concepto, 'Unidad'),
                'Descripcion': _attr(concepto, 'Descripcion'),
                'ValorUnitario': _attr(concepto, 'ValorUnitario'),
                'Importe': _attr(concepto, 'Importe'),
                'Descuento': _attr(concepto, 'Descuento', '0.00'),
                'ObjetoImp': _attr(concepto, 'ObjetoImp'),
            }
            
            # Formateo
            c['CantidadFmt'] = str(_decimal(c['Cantidad'], 6)).rstrip('0').rstrip('.')
            c['ValorUnitarioFmt'] = _format_money(c['ValorUnitario'])
            c['ImporteFmt'] = _format_money(c['Importe'])
            c['DescuentoFmt'] = _format_money(c['Descuento'])
            
            # Impuestos por concepto
            c['Traslados'] = []
            c['Retenciones'] = []
            
            imp_node = concepto.find('cfdi:Impuestos', NS)
            if imp_node is not None:
                traslados = imp_node.find('cfdi:Traslados', NS)
                if traslados is not None:
                    for t in traslados.findall('cfdi:Traslado', NS):
                        traslado = {
                            'Base': _attr(t, 'Base'),
                            'Impuesto': _attr(t, 'Impuesto'),
                            'ImpuestoDesc': CATALOGO_IMPUESTO.get(_attr(t, 'Impuesto'), ''),
                            'TipoFactor': _attr(t, 'TipoFactor'),
                            'TasaOCuota': _attr(t, 'TasaOCuota'),
                            'Importe': _attr(t, 'Importe'),
                        }
                        tasa = _decimal(traslado['TasaOCuota'], 6)
                        traslado['TasaPct'] = f"{tasa * 100:.2f}%"
                        traslado['ImporteFmt'] = _format_money(traslado['Importe'])
                        c['Traslados'].append(traslado)
                
                retenciones = imp_node.find('cfdi:Retenciones', NS)
                if retenciones is not None:
                    for r in retenciones.findall('cfdi:Retencion', NS):
                        retencion = {
                            'Base': _attr(r, 'Base'),
                            'Impuesto': _attr(r, 'Impuesto'),
                            'ImpuestoDesc': CATALOGO_IMPUESTO.get(_attr(r, 'Impuesto'), ''),
                            'TipoFactor': _attr(r, 'TipoFactor'),
                            'TasaOCuota': _attr(r, 'TasaOCuota'),
                            'Importe': _attr(r, 'Importe'),
                        }
                        retencion['ImporteFmt'] = _format_money(retencion['Importe'])
                        c['Retenciones'].append(retencion)
            
            conceptos.append(c)
    
    # --- IMPUESTOS GLOBALES ---
    impuestos_global = {
        'TotalImpuestosTrasladados': '0.00',
        'TotalImpuestosRetenidos': '0.00',
        'Traslados': [],
        'Retenciones': [],
    }
    
    imp_global_node = root.find('cfdi:Impuestos', NS)
    if imp_global_node is not None:
        impuestos_global['TotalImpuestosTrasladados'] = _attr(
            imp_global_node, 'TotalImpuestosTrasladados', '0.00'
        )
        impuestos_global['TotalImpuestosRetenidos'] = _attr(
            imp_global_node, 'TotalImpuestosRetenidos', '0.00'
        )
        
        traslados = imp_global_node.find('cfdi:Traslados', NS)
        if traslados is not None:
            for t in traslados.findall('cfdi:Traslado', NS):
                traslado = {
                    'Base': _attr(t, 'Base'),
                    'Impuesto': _attr(t, 'Impuesto'),
                    'ImpuestoDesc': CATALOGO_IMPUESTO.get(_attr(t, 'Impuesto'), ''),
                    'TipoFactor': _attr(t, 'TipoFactor'),
                    'TasaOCuota': _attr(t, 'TasaOCuota'),
                    'Importe': _attr(t, 'Importe'),
                }
                tasa = _decimal(traslado['TasaOCuota'], 6)
                traslado['TasaPct'] = f"{tasa * 100:.2f}%"
                traslado['ImporteFmt'] = _format_money(traslado['Importe'])
                traslado['BaseFmt'] = _format_money(traslado['Base'])
                impuestos_global['Traslados'].append(traslado)
        
        retenciones = imp_global_node.find('cfdi:Retenciones', NS)
        if retenciones is not None:
            for r in retenciones.findall('cfdi:Retencion', NS):
                retencion = {
                    'Impuesto': _attr(r, 'Impuesto'),
                    'ImpuestoDesc': CATALOGO_IMPUESTO.get(_attr(r, 'Impuesto'), ''),
                    'Importe': _attr(r, 'Importe'),
                }
                retencion['ImporteFmt'] = _format_money(retencion['Importe'])
                impuestos_global['Retenciones'].append(retencion)
    
    impuestos_global['TotalImpuestosTrasladadosFmt'] = _format_money(
        impuestos_global['TotalImpuestosTrasladados']
    )
    impuestos_global['TotalImpuestosRetenidosFmt'] = _format_money(
        impuestos_global['TotalImpuestosRetenidos']
    )
    
    # --- TIMBRE FISCAL DIGITAL (TFD) ---
    tfd_node = root.find('.//tfd:TimbreFiscalDigital', NS)
    timbre = {}
    if tfd_node is not None:
        timbre = {
            'Version': _attr(tfd_node, 'Version'),
            'UUID': _attr(tfd_node, 'UUID'),
            'FechaTimbrado': _attr(tfd_node, 'FechaTimbrado'),
            'RfcProvCertif': _attr(tfd_node, 'RfcProvCertif'),
            'SelloCFD': _attr(tfd_node, 'SelloCFD'),
            'NoCertificadoSAT': _attr(tfd_node, 'NoCertificadoSAT'),
            'SelloSAT': _attr(tfd_node, 'SelloSAT'),
        }
        if timbre['FechaTimbrado']:
            timbre['FechaTimbradoFmt'] = timbre['FechaTimbrado'].replace('T', ' ')
    
    # --- CADENA ORIGINAL DEL TFD ---
    cadena_original = _generar_cadena_original_tfd(tfd_node)
    
    # --- URL y datos para QR ---
    qr_url = ''
    if timbre.get('UUID') and emisor.get('Rfc') and receptor.get('Rfc'):
        total_10dec = _decimal(comprobante['Total'], 10)
        sello_emisor = comprobante.get('Sello', '')
        fe = sello_emisor[-8:] if len(sello_emisor) >= 8 else sello_emisor
        qr_url = (
            f"https://verificacfdi.facturaelectronica.sat.gob.mx/default.aspx"
            f"?id={timbre['UUID']}"
            f"&re={emisor['Rfc']}"
            f"&rr={receptor['Rfc']}"
            f"&tt={total_10dec}"
            f"&fe={fe}"
        )
    
    # --- RESUMEN FISCAL (Para reportes y DB) ---
    resumen = {
        'subtotal': _decimal(comprobante.get('SubTotal', 0)),
        'descuento': _decimal(comprobante.get('Descuento', 0)),
        'total': _decimal(comprobante.get('Total', 0)),
        'iva_16': Decimal('0.00'),
        'iva_8': Decimal('0.00'),
        'iva_0': Decimal('0.00'),
        'iva_exento': Decimal('0.00'),
        'iva_ret': Decimal('0.00'),
        'isr_ret': Decimal('0.00'),
        'ieps': Decimal('0.00'),
        'otros_traslados': Decimal('0.00'),
        'otros_retenciones': Decimal('0.00'),
    }

    # Procesar Traslados Globales
    for t in impuestos_global['Traslados']:
        imp = t.get('Impuesto')
        tasa = _decimal(t.get('TasaOCuota'), 6)
        importe = _decimal(t.get('Importe'))
        
        if imp == '002': # IVA
            if tasa == Decimal('0.160000'): resumen['iva_16'] += importe
            elif tasa == Decimal('0.080000'): resumen['iva_8'] += importe
            elif tasa == Decimal('0.000000'): resumen['iva_0'] += importe
            else: resumen['otros_traslados'] += importe
        elif imp == '003': # IEPS
            resumen['ieps'] += importe
        else:
            resumen['otros_traslados'] += importe

    # Procesar Retenciones Globales
    for r in impuestos_global['Retenciones']:
        imp = r.get('Impuesto')
        importe = _decimal(r.get('Importe'))
        if imp == '001': # ISR
            resumen['isr_ret'] += importe
        elif imp == '002': # IVA Ret
            resumen['iva_ret'] += importe
        else:
            resumen['otros_retenciones'] += importe

    # Convertir Decimales de resumen a strings para el retorno
    resumen_fmt = {k: str(v) for k, v in resumen.items()}

    return {
        'comprobante': comprobante,
        'emisor': emisor,
        'receptor': receptor,
        'conceptos': conceptos,
        'impuestos': impuestos_global,
        'resumen_fiscal': resumen_fmt,
        'timbre': timbre,
        'cadena_original': cadena_original,
        'qr_url': qr_url,
        'xml_raw': xml_content.decode('utf-8', errors='replace') if isinstance(xml_content, bytes) else xml_content,
    }


def _generar_cadena_original_tfd(tfd_node):
    """
    Genera la Cadena Original del Complemento de Certificación Digital del SAT.
    Formato: ||version|UUID|FechaTimbrado|RfcProvCertif|SelloCFD|NoCertificadoSAT||
    
    Nota: En producción, se recomienda usar el XSLT oficial del SAT:
    https://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/cadenaoriginal_TFD_1_1.xslt
    Esta implementación replica el resultado del XSLT para el nodo TFD 1.1.
    """
    if tfd_node is None:
        return ''
    
    campos = [
        _attr(tfd_node, 'Version'),
        _attr(tfd_node, 'UUID'),
        _attr(tfd_node, 'FechaTimbrado'),
        _attr(tfd_node, 'RfcProvCertif'),
        _attr(tfd_node, 'SelloCFD'),
        _attr(tfd_node, 'NoCertificadoSAT'),
    ]
    
    # Filtrar vacíos y unir con pipes
    campos_limpios = [c.strip() for c in campos if c.strip()]
    return '||' + '|'.join(campos_limpios) + '||'


def _numero_a_letras(numero, moneda='MXN'):
    """Convierte un número a su representación en letras (para totales en factura)."""
    try:
        num = Decimal(str(numero))
    except Exception:
        return ''
    
    parte_entera = int(num)
    centavos = int((num - parte_entera) * 100)
    
    unidades = ['', 'UN', 'DOS', 'TRES', 'CUATRO', 'CINCO', 'SEIS', 'SIETE', 'OCHO', 'NUEVE']
    decenas = ['', 'DIEZ', 'VEINTE', 'TREINTA', 'CUARENTA', 'CINCUENTA',
               'SESENTA', 'SETENTA', 'OCHENTA', 'NOVENTA']
    especiales = {
        11: 'ONCE', 12: 'DOCE', 13: 'TRECE', 14: 'CATORCE', 15: 'QUINCE',
        16: 'DIECISÉIS', 17: 'DIECISIETE', 18: 'DIECIOCHO', 19: 'DIECINUEVE',
        21: 'VEINTIÚN', 22: 'VEINTIDÓS', 23: 'VEINTITRÉS', 24: 'VEINTICUATRO',
        25: 'VEINTICINCO', 26: 'VEINTISÉIS', 27: 'VEINTISIETE', 28: 'VEINTIOCHO',
        29: 'VEINTINUEVE',
    }
    centenas_txt = ['', 'CIENTO', 'DOSCIENTOS', 'TRESCIENTOS', 'CUATROCIENTOS',
                    'QUINIENTOS', 'SEISCIENTOS', 'SETECIENTOS', 'OCHOCIENTOS', 'NOVECIENTOS']
    
    def _convertir_grupo(n):
        if n == 0:
            return ''
        if n == 100:
            return 'CIEN'
        if n in especiales:
            return especiales[n]
        
        resultado = ''
        c = n // 100
        d = (n % 100) // 10
        u = n % 10
        
        if c > 0:
            resultado += centenas_txt[c]
        
        resto = n % 100
        if resto in especiales:
            if resultado:
                resultado += ' '
            resultado += especiales[resto]
        else:
            if d > 0:
                if resultado:
                    resultado += ' '
                resultado += decenas[d]
            if u > 0:
                if d > 0:
                    resultado += ' Y '
                elif resultado:
                    resultado += ' '
                resultado += unidades[u]
        
        return resultado
    
    if parte_entera == 0:
        letras = 'CERO'
    else:
        millones = parte_entera // 1_000_000
        miles = (parte_entera % 1_000_000) // 1_000
        centenas = parte_entera % 1_000
        
        partes = []
        if millones > 0:
            if millones == 1:
                partes.append('UN MILLÓN')
            else:
                partes.append(_convertir_grupo(millones) + ' MILLONES')
        if miles > 0:
            if miles == 1:
                partes.append('MIL')
            else:
                partes.append(_convertir_grupo(miles) + ' MIL')
        if centenas > 0:
            partes.append(_convertir_grupo(centenas))
        
        letras = ' '.join(partes)
    
    moneda_txt = {'MXN': 'M.N.', 'USD': 'USD', 'EUR': 'EUR'}.get(moneda, moneda)
    return f"{letras} PESOS {centavos:02d}/100 {moneda_txt}"


def validate_cfdi_40(data):
    """
    Valida que el XML contiene los campos obligatorios de CFDI 4.0
    para poder generar una representación impresa válida.
    """
    errors = []
    warnings = []
    
    # Validar versión
    if data['comprobante']['Version'] != '4.0':
        warnings.append(f"Versión del CFDI: {data['comprobante']['Version']} (se esperaba 4.0)")
    
    # Emisor
    if not data['emisor']['Rfc']:
        errors.append('RFC del Emisor es obligatorio')
    if not data['emisor']['Nombre']:
        errors.append('Nombre del Emisor es obligatorio en CFDI 4.0')
    if not data['emisor']['RegimenFiscal']:
        errors.append('Régimen Fiscal del Emisor es obligatorio')
    
    # Receptor
    if not data['receptor']['Rfc']:
        errors.append('RFC del Receptor es obligatorio')
    if not data['receptor']['Nombre']:
        errors.append('Nombre del Receptor es obligatorio en CFDI 4.0')
    if not data['receptor']['DomicilioFiscalReceptor']:
        warnings.append('Domicilio Fiscal del Receptor no encontrado (obligatorio en CFDI 4.0)')
    if not data['receptor']['RegimenFiscalReceptor']:
        warnings.append('Régimen Fiscal del Receptor no encontrado (obligatorio en CFDI 4.0)')
    
    # Timbre
    if not data['timbre'].get('UUID'):
        warnings.append('UUID (Folio Fiscal) no encontrado — el CFDI puede no estar timbrado')
    if not data['timbre'].get('SelloSAT'):
        warnings.append('Sello SAT no encontrado')
    
    # Conceptos
    if not data['conceptos']:
        errors.append('No se encontraron conceptos en el CFDI')
    
    return {'errors': errors, 'warnings': warnings, 'valid': len(errors) == 0}
