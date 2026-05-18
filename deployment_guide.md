# Guía de Despliegue en Producción: Módulo CFDI_PDF

Esta guía contiene las instrucciones necesarias para desplegar la aplicación en un entorno de producción, ya sea en un servidor propio (VPS) o utilizando plataformas en la nube gratuitas y confiables (**Fly.io** o **Render.com**).

---

## Opción 1: Despliegue en la Nube con Fly.io (Recomendada) 🚀
Fly.io es la mejor opción para esta aplicación porque ofrece **contenedores Docker** y **3GB de almacenamiento persistente gratis**, lo que evita que tu base de datos SQLite (`cfdi_data.db`) se borre al reiniciar el servidor.

### Paso 1: Instalar Fly CLI
Abre tu terminal y corre el instalador según tu sistema operativo:
* **macOS / Linux:**
  ```bash
  curl -L https://fly.io/install.sh | sh
  ```
* **Windows (PowerShell):**
  ```powershell
  iwr https://fly.io/install.ps1 -useb | iex
  ```

### Paso 2: Iniciar Sesión y Registrarse
Crea una cuenta gratuita si aún no la tienes:
```bash
fly auth signup
```
O inicia sesión si ya tienes cuenta:
```bash
fly auth login
```

### Paso 3: Inicializar la App en Fly.io
Desde la carpeta raíz del proyecto `CFDI_PDF`, ejecuta:
```bash
fly launch
```
* **¿Usar la configuración existente?** Te preguntará si quieres usar el archivo `fly.toml` existente. Escribe `y` (Sí).
* **Copiar base de datos:** Te preguntará si deseas desplegar la aplicación. Elige que **aún no**, ya que primero debemos crear el disco de almacenamiento persistente.

### Paso 4: Crear el Disco Persistente Gratuito
Para que no se borren tus facturas, crea un volumen de disco (de 1GB es más que suficiente, tienes hasta 3GB gratis):
```bash
fly volumes create cfdi_data --region qro --size 1
```
*(Ajusta la región `--region qro` para Querétaro, México, o la que hayas seleccionado en el paso 3).*

### Paso 5: Desplegar
Ahora sí, sube la aplicación a producción con:
```bash
fly deploy
```
Al finalizar, la terminal te dará una URL segura (ej: `https://modulo-de-facturas.fly.dev`) con certificado HTTPS automático y ¡lista para compartir!

---

## Opción 2: Despliegue en Render.com (Fácil con GitHub) ☁️
Render compila tu aplicación automáticamente cada vez que haces un `git push` a tu repositorio.

### Paso 1: Configurar Base de Datos Externa (Requerido para plan gratis)
Dado que el almacenamiento gratuito de Render se borra al reiniciar, debes conectar tu app a una base de datos PostgreSQL gratuita:
1. Crea una cuenta en [Supabase.com](https://supabase.com) o [Neon.tech](https://neon.tech) (ambos son gratuitos y extremadamente seguros).
2. Crea un proyecto y copia la **Connection String** de tu base de datos PostgreSQL.
3. *Nota:* Si decides usar esta opción, hazmelo saber para actualizar `server.py` de SQLite a PostgreSQL en menos de un minuto.

### Paso 2: Crear el servicio en Render
1. Entra a [dashboard.render.com](https://dashboard.render.com) y haz clic en **New > Web Service**.
2. Conecta tu repositorio de GitHub `Modulo-de-Facturas`.
3. Configura los siguientes campos:
   * **Language:** `Docker` (Render detectará automáticamente nuestro `Dockerfile`).
   * **Region:** Selecciona la más cercana a ti.
   * **Instance Type:** `Free` ($0/month).
4. En la pestaña **Environment**, agrega tus variables de entorno si es necesario (como la URL de tu base de datos si migraste a PostgreSQL).
5. Haz clic en **Deploy Web Service** y ¡listo! Tu app estará en línea.

---

## Opción 3: Pruebas Locales con Docker 🐳
Si tienes Docker instalado en tu computadora y quieres verificar el contenedor antes de subirlo:

```bash
# 1. Compilar y levantar la aplicación
docker-compose up --build -d

# 2. Entrar en el navegador
# Abre http://localhost:8080

# 3. Detener la aplicación sin perder datos
docker-compose down
```
*La base de datos SQLite se guardará en un volumen virtual de Docker llamado `cfdi_data` y no se perderá al apagar el contenedor.*

---

## Opción 4: Servidor Propio / VPS (Ubuntu/Debian) 🖥️
Si prefieres usar un servidor tradicional sin Docker:

### 1. Requisitos de Sistema (Librerías C para WeasyPrint)
```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libffi-dev shared-mime-info gobject-introspection libgirepository1.0-dev libcairo2
```

### 2. Entorno Virtual de Python
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Ejecución en Producción con Gunicorn
```bash
gunicorn --workers 4 --bind 0.0.0.0:8080 wsgi:app
```
*Se recomienda configurar Nginx al frente como proxy inverso y Systemd para mantener el proceso corriendo en segundo plano.*

---
**Guía Actualizada por:** Antigravity AI Agent
**Fecha de actualización:** Mayo 2026
