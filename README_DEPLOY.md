# ARTHASECURE 1.5 — modo web y LAN

## Funcionamiento automático
- **LAN/Windows:** ejecuta `run.bat`. Flask escucha en `0.0.0.0:5000`, muestra la URL local y detecta la IP LAN. Desde otro equipo o móvil de la misma Wi-Fi abre `http://IP-LAN-DEL-PC:5000`. Permite Python en el Firewall de Windows solo en redes privadas.
- **Internet/Render:** despliega el mismo repositorio con Gunicorn: `gunicorn app:app --bind 0.0.0.0:$PORT`. Render detecta el entorno y activa cookies seguras HTTPS.
- En Render, los análisis se ejecutan desde el servidor remoto y no pueden alcanzar equipos privados de la LAN. Para analizar tu LAN, inicia la versión local en un equipo conectado a esa red.

## Prueba gratuita
La página `/tools` y las API de análisis permiten visitantes sin iniciar sesión. Cada sesión de navegador dispone de hasta 3 auditorías gratuitas. Un análisis IP seguido de un escaneo de puertos asociado consume una sola auditoría; un escaneo de puertos independiente consume una. El contador se guarda en la cookie de sesión firmada, por lo que borrar cookies o cambiar de navegador puede reiniciar la prueba. No equivale a un sistema comercial antifraude.

Los usuarios autenticados conservan el acceso ilimitado. En Render configura `FLASK_SECRET_KEY`, `ADMIN_USERNAME` y `ADMIN_PASSWORD`. No uses contraseñas predeterminadas.

## Configuración Render
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --bind 0.0.0.0:$PORT`
- Variables: `FLASK_SECRET_KEY` (aleatoria y privada), `ADMIN_USERNAME`, `ADMIN_PASSWORD`.

## Seguridad
En el hosting público se bloquean objetivos privados/no globales. Solo analiza sistemas públicos para los que tengas autorización. En modo LAN se aceptan IP privadas para que puedas auditar tu propia red local; no abras el puerto 5000 al Internet ni configures port forwarding.

## Persistencia
Render Free puede suspender el servicio tras inactividad y su disco es efímero. SQLite e informes PDF pueden perderse tras reinicios o despliegues. Para conservar historial, configura almacenamiento persistente o migra a una base de datos gestionada.
