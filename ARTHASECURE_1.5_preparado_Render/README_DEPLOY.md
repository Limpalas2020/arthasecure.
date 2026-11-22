# ARTHASECURE 1.5 — despliegue en Render

## Requisitos de seguridad antes de publicar
Esta edición preparada para despliegue:
- exige `FLASK_SECRET_KEY`;
- exige sesión iniciada para herramientas, dashboard, estadísticas, APIs de análisis y descarga de informes;
- no crea la cuenta insegura `admin/admin`;
- crea el administrador inicial solo si se configuran `ADMIN_USERNAME` y `ADMIN_PASSWORD`;
- bloquea objetivos IP no globales desde el servidor público;
- limita cada escaneo a 100 puertos válidos.

## Publicar
1. Sube el contenido de esta carpeta a un repositorio **privado** de GitHub.
2. En Render: New + Web Service y conecta el repositorio.
3. Runtime: Python 3.
4. Build Command: `pip install -r requirements.txt`
5. Start Command: `gunicorn app:app --bind 0.0.0.0:$PORT`
6. En Environment agrega:
   - `FLASK_SECRET_KEY`: una cadena aleatoria larga y privada (mínimo 32 caracteres).
   - `ADMIN_USERNAME`: nombre de usuario nuevo.
   - `ADMIN_PASSWORD`: contraseña larga y única.
7. Crea el servicio y espera a que el deploy termine.
8. Abre la URL `https://<nombre-del-servicio>.onrender.com` desde el teléfono e inicia sesión en `/login`.

## Importante sobre el plan gratuito
Render Free puede suspender el servicio tras 15 minutos sin actividad y el primer acceso posterior puede tardar alrededor de un minuto. Su sistema de archivos es efímero: la base SQLite y los PDF creados pueden perderse al reiniciar o desplegar. Esta versión sirve para una prueba, no para conservar historial de producción.

## Alcance de los escaneos
Los análisis se ejecutan desde el servidor alojado en Render, no desde el teléfono ni desde la red Wi-Fi del teléfono. Solo analiza sistemas públicos sobre los que tengas autorización. Las direcciones privadas de tu red local no son alcanzables desde el servidor de Internet.
