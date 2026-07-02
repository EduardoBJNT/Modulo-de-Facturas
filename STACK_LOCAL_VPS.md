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

## Integracion con Cuentas por Pagar

Si Cuentas por Pagar necesita facturas desde este modulo, debe consumirlas por API o exportacion/importacion. No se recomienda compartir directamente la base SQLite.
