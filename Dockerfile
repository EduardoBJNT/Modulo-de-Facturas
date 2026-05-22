FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc en disco y habilitar el buffer de logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Configurar directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema requeridas por WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    python3-cffi \
    python3-brotli \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libffi-dev \
    shared-mime-info \
    gobject-introspection \
    libgirepository1.0-dev \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

# Crear carpetas requeridas y asegurar permisos
RUN mkdir -p uploads static templates

# Puerto expuesto (estándar para la nube)
EXPOSE 8080

# Comando para ejecutar con Gunicorn en producción, leyendo dinámicamente el PORT de Render
CMD ["sh", "-c", "gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8080} wsgi:app"]
