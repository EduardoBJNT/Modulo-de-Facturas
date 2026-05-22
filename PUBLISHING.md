# Publicación del módulo

Este repositorio se mantiene enfocado en:

- carga de XML CFDI;
- listado y búsqueda de facturas;
- vista previa HTML;
- impresión y descarga PDF;
- persistencia local con SQLite;
- despliegue preparado para contenedor.

El flujo de publicación está pensado para evitar arrastrar archivos locales innecesarios.

## Publicar cuando se indique

Ejecutar:

```bash
bash scripts/publish.sh "mensaje del cambio"
```

El script:

- toma solo cambios reales del repositorio;
- evita incluir artefactos locales;
- crea el commit;
- hace push al remoto `origin`.

## Archivos locales que no deben subir

Los siguientes archivos y carpetas permanecen fuera del repositorio:

- `.logs/`
- `.venv/`
- `cfdi_data.db`
- `uploads/`
- `test_output.pdf`
- `curl_test.pdf`
- `STACK_LOCAL_VPS.md`
- `run-local.sh`
- `render.yaml`
