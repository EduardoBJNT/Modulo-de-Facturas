# Guía de Despliegue Enterprise: Módulo CFDI_PDF

Esta guía contiene las instrucciones necesarias para que un administrador de sistemas o desarrollador despliegue la aplicación en un entorno de servidor robusto.

## 1. Requisitos de Sistema
La aplicación utiliza **WeasyPrint** para la generación de PDFs, la cual requiere librerías de renderizado de fuentes y gráficos en el sistema operativo:

### En Linux (Ubuntu/Debian):
```bash
sudo apt-get update
sudo apt-get install python3-pip python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

### En Windows:
Se recomienda instalar las GTK+ Runtime libraries necesarias para WeasyPrint.

## 2. Configuración del Entorno Python
Se recomienda el uso de un entorno virtual para aislar las dependencias:

```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# o venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt
```

## 3. Ejecución en Producción
Para un entorno multiusuario real, **NO** utilizar `python server.py`. En su lugar, utilizar un servidor WSGI como **Gunicorn** (incluido en requirements.txt):

```bash
# Comando de ejecución recomendado
gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app
```
*Ajustar `--workers` según el número de núcleos de CPU del servidor.*

## 4. Persistencia de Datos
- La aplicación usa actualmente **SQLite** (`cfdi_data.db`).
- Asegurarse de que el usuario que corre el proceso tenga permisos de escritura en la carpeta del proyecto.
- **Escalabilidad:** Si el volumen supera los 100,000 registros, se recomienda migrar el engine de base de datos a PostgreSQL. El código es compatible con SQLAlchemy con cambios mínimos.

## 5. Recomendaciones de Seguridad
1. **Nginx/Apache:** Utilizar un servidor proxy inverso (como Nginx) al frente de Gunicorn para manejar SSL (HTTPS) y servir archivos estáticos.
2. **Carga de Archivos:** El límite de carga está configurado en 256MB en `server.py` (`MAX_CONTENT_LENGTH`). Ajustar según política de la empresa.
3. **Logs:** Los errores de parsing se imprimen en consola; se recomienda redirigirlos a un archivo de log centralizado.

---
**Desarrollado por:** Antigravity AI Agent
**Contexto:** Enterprise Fiscal/Contable Operativo
