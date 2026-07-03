# Stack Local y VPS

Esta aplicacion se mantiene independiente de Cuentas por Pagar.

## Responsabilidad

`CFDI_PDF` administra facturas recibidas:

- carga de XML CFDI;
- parsing fiscal;
- almacenamiento de CFDI;
- generacion de representacion impresa PDF.

No debe contener la logica principal de conciliacion de Cuentas por Pagar.

## Stack

- Backend: Python + Flask.
- Servidor produccion: Gunicorn.
- Base local: SQLite.
- Contenedor: Docker.
- Persistencia VPS: disco persistente montado en `/app/data`.

## Uso local

```bash
./run-local.sh
```

URL local:

```text
http://localhost:5050
```

## Uso con Docker local

```bash
docker compose up --build
```

URL local Docker:

```text
http://localhost:8080
```

## Despliegue VPS/Render

El archivo `render.yaml` deja preparado el servicio Docker con disco persistente.
En produccion, configurar `DB_PATH=/app/data/cfdi_data.db`.

Variables recomendadas para autenticacion y recuperacion de password:

```text
APP_PUBLIC_URL=https://tu-dominio.com
APP_SECRET_KEY=valor-largo-aleatorio
ALLOW_USER_REGISTRATION=0
APP_ADMIN_USER=admin@tu-dominio.com
APP_ADMIN_PASSWORD=password-inicial-seguro
SMTP_HOST=smtp.tu-proveedor.com
SMTP_PORT=587
SMTP_USER=usuario-smtp
SMTP_PASSWORD=password-smtp
SMTP_FROM=no-reply@tu-dominio.com
SMTP_USE_TLS=1
SESSION_COOKIE_SECURE=1
```

## Integracion con Cuentas por Pagar

Si Cuentas por Pagar necesita facturas desde este modulo, debe consumirlas por API o exportacion/importacion. No se recomienda compartir directamente la base SQLite.
