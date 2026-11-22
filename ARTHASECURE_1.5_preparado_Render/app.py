"""
===============================================================================
SERVIDOR WEB Y CONTROLADOR PRINCIPAL DE LA APLICACIÓN (FLASK WSGI)
===============================================================================

Este archivo constituye el punto de entrada (Entry Point) y la capa controladora
(Controller en el patrón arquitectónico MVC) de la plataforma CIBER-ANALYZER.

ARQUITECTURA Y FLUJO DE COMUNICACIÓN (MODELO - VISTA - CONTROLADOR):
-------------------------------------------------------------------
1. El Controlador (app.py):
   - Escucha las solicitudes HTTP en el puerto TCP 5000 (interfaz WSGI).
   - Enruta cada petición según el método (GET/POST) y la URL solicitada.
   - Valida la estructura de los datos entrantes (JSON o formularios).
   - Delega la lógica de negocio a los módulos especializados ('modules/').
   - Orquesta la respuesta final: renderiza plantillas HTML mediante Jinja2
     o devuelve respuestas serializadas en formato JSON (API REST).

2. El Modelo (modules/database.py, ip_tracker.py, port_scanner.py):
   - Contiene la lógica pura de telecomunicaciones, sockets y persistencia relacional.
   - Es totalmente independiente de la interfaz web (puede reutilizarse en una CLI).

3. La Vista (views/*.html, public/css/main.css, public/js/main.js):
   - Presenta la interfaz visual al usuario en el navegador web.
   - Consume los endpoints del backend asíncronamente mediante Fetch API sin recargas.
"""

# ==============================================================================
# IMPORTACIÓN DE BIBLIOTECAS DEL SISTEMA Y FLASK
# ==============================================================================
import os                      # Interacción con el sistema operativo (cálculo de rutas absolutas).
import ipaddress
from functools import wraps
from datetime import datetime  # Gestión de fechas para inyección global en plantillas.

# Componentes fundamentales del microframework Flask
from flask import (
    Flask,            # Clase central de la aplicación WSGI.
    render_template,  # Función que procesa y renderiza plantillas HTML con el motor Jinja2.
    request,          # Objeto global de contexto que encapsula la petición HTTP activa (headers, body, IP).
    jsonify,          # Serializa diccionarios de Python a respuestas HTTP con cabecera 'application/json'.
    send_file,        # Transmite archivos binarios desde el disco al cliente (descarga de PDFs).
    abort,            # Interrumpe la ejecución y devuelve un código de estado de error HTTP (ej. 404).
    url_for,          # Genera URLs dinámicas basadas en el nombre de la función de vista.
    redirect,         # Redirecciona al navegador hacia otra ruta URL.
    session           # Almacén de sesión criptográfico en cookies firmadas por el servidor.
)

# ==============================================================================
# IMPORTACIÓN DE LOS MÓDULOS DE LÓGICA DE NEGOCIO Y PERSISTENCIA
# ==============================================================================
from modules import database       # Capa de datos SQLite 3 y KPIs analíticos.
from modules import ip_tracker     # Validación de IP, clasificación RFC y geolocalización OSINT.
from modules import port_scanner   # Escaneo concurrente de puertos TCP con ThreadPoolExecutor.
from modules import pdf_generator  # Compilación de informes técnicos en PDF con ReportLab.
from modules import vuln_scanner   # Evaluación defensiva de vulnerabilidades, CVEs y riesgos de red.

# ==============================================================================
# CONFIGURACIÓN DE RUTAS BASE Y CREACIÓN DE LA INSTANCIA FLASK
# ==============================================================================
# ¿Por qué definimos rutas absolutas para las plantillas y archivos estáticos?
# Flask por defecto busca las carpetas 'templates' y 'static'. En este proyecto,
# la arquitectura organiza las vistas en 'views/' y los recursos en 'public/'.
# Al pasar 'template_folder' y 'static_folder' con rutas absolutas basadas en '__file__',
# garantizamos que el servidor encuentre sus archivos sin importar desde qué directorio
# fue lanzado el comando en la terminal.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "views")
STATIC_DIR = os.path.join(BASE_DIR, "public")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

# Clave secreta fija/estable para la gestión de sesiones criptográficas y protección CSRF.
# Una clave fija evita que las sesiones se cierren automáticamente cada vez que el servidor se reinicia.
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError("Falta configurar FLASK_SECRET_KEY en las variables de entorno.")

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# LÍMITE DE ANÁLISIS EN LA VERSIÓN DE PRUEBA GRATUITA:
# Define cuántos escaneos de red puede realizar un usuario antes de requerir iniciar sesión con su cuenta de pago.
FREE_TIER_LIMIT = 3

# Inicializar automáticamente las tablas e índices de la base de datos al arrancar
database.init_db()


def login_required(view):
    """Exige una sesión válida para las herramientas y los datos privados."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id or not database.get_user_by_id(user_id):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Debes iniciar sesión."}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view


def validate_public_target(target):
    """Solo permite destinos públicos; el servidor remoto no debe sondear redes privadas."""
    valid, resolved_ip, _, err_msg = ip_tracker.validate_and_parse_target(target)
    if not valid:
        return False, None, err_msg
    try:
        address = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return False, None, "No se pudo validar la dirección IP resuelta."
    if not address.is_global:
        return False, None, "En el servicio publicado solo se permiten objetivos IP públicos y autorizados."
    return True, resolved_ip, None


@app.context_processor
def inject_global_template_vars():
    """
    Inyector de contexto global para el motor de plantillas Jinja2.

    ¿Cómo funciona?
    Cualquier variable retornada por este diccionario estará automáticamente
    disponible en TODAS las plantillas HTML (base.html, index.html, tools.html, etc.)
    sin necesidad de pasarla manualmente en cada llamada a render_template.

    VARIABLES INYECTADAS:
    - current_year: Año en curso para el footer.
    - current_user: Diccionario con la información del usuario autenticado (o None).
    - is_authenticated: Booleano True si el usuario inició sesión, False si está en prueba gratuita.
    - free_limit: Límite máximo de escaneos gratuitos (FREE_TIER_LIMIT = 3).
    - free_usage_count: Cantidad de escaneos consumidos en la sesión actual.
    - free_usage_left: Cantidad de análisis restantes en la prueba gratuita.
    - is_limit_reached: Booleano True si agotó los usos gratuitos y no ha iniciado sesión.
    """
    user_id = session.get("user_id")
    current_user = database.get_user_by_id(user_id) if user_id else None
    is_auth = bool(current_user)

    free_count = session.get("free_usage_count", 0)
    free_left = max(0, FREE_TIER_LIMIT - free_count) if not is_auth else 999999
    limit_reached = (free_count >= FREE_TIER_LIMIT) if not is_auth else False

    return {
        "current_year": datetime.now().year,
        "current_user": current_user,
        "is_authenticated": is_auth,
        "free_limit": FREE_TIER_LIMIT,
        "free_usage_count": free_count,
        "free_usage_left": free_left,
        "is_limit_reached": limit_reached
    }


# ==============================================================================
# RUTAS DE VISTAS (CONTROLADORES DE PÁGINAS HTML)
# ==============================================================================

@app.route("/")
def index():
    """
    Ruta raíz / Portada institucional del sistema.

    Renderiza 'views/index.html', pasando 'active_page="index"' para que la barra
    de navegación superior (navbar) resalte visualmente la opción 'Inicio' mediante CSS.
    """
    return render_template("index.html", active_page="index")


@app.route("/tools")
@login_required
def tools():
    """
    Consola interactiva de auditoría (Rastreo IP y Escaneo de Puertos TCP).

    Pasa al frontend el diccionario 'PRESET_PORTS' proveniente de port_scanner.py,
    permitiendo a la plantilla 'tools.html' renderizar dinámicamente los botones
    de perfiles rápidos (Web, Esenciales, Base de Datos, Acceso Remoto).
    """
    return render_template(
        "tools.html",
        active_page="tools",
        preset_ports=port_scanner.PRESET_PORTS
    )


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Panel centralizado de telemetría y métricas analíticas.

    Flujo de datos:
    1. Llama a 'database.get_dashboard_stats()' para calcular los KPIs acumulados
       y las distribuciones de gráficos (Chart.js) ejecutando agregaciones SQL.
    2. Llama a 'database.get_all_reports()' para listar los informes PDF emitidos.
    3. Renderiza 'dashboard.html' inyectando tanto las métricas como la lista de reportes.
    """
    stats = database.get_dashboard_stats()
    reports = database.get_all_reports()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        reports=reports
    )


# ==============================================================================
# RUTAS DE AUTENTICACIÓN Y SESIÓN (CUENTAS DE PAGO / ACCESO ILIMITADO)
# ==============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Controlador de inicio de sesión para usuarios registrados / cuentas de pago.

    Permite autenticar a los usuarios autorizados (por ejemplo, el usuario inicial 'admin'
    con contraseña 'admin').
    
    FLUJO TÉCNICO:
    1. Si el usuario ya cuenta con una sesión activa válida en cookies, se le redirige
       inmediatamente a la consola de herramientas ('/tools').
    2. En petición GET: renderiza la plantilla 'views/login.html' con el formulario visual.
    3. En petición POST:
       - Extrae 'username' y 'password' enviados desde el formulario.
       - Invoca 'database.verify_user(username, password)', que consulta la tabla 'users'
         y valida el hash PBKDF2:SHA256 con Werkzeug.
       - Si es válido: inicializa 'session["user_id"]', 'session["username"]', 'session["role"]'
         y 'session["plan"] = "unlimited"'.
       - Redirige al usuario a la consola con acceso ilimitado desbloqueado.
       - Si es inválido: devuelve la vista con mensaje de error sin revelar detalles internos.
    """
    # Si ya inició sesión, redirigir a herramientas
    user_id = session.get("user_id")
    if user_id and database.get_user_by_id(user_id):
        return redirect(url_for("tools"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Por favor ingrese su nombre de usuario y contraseña."
        else:
            user = database.verify_user(username, password)
            if user:
                # Establecer sesión autenticada en cookie firmada
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["plan"] = user.get("plan", "unlimited")

                # Redirección amigable si venía de un enlace protegido
                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                return redirect(url_for("tools"))
            else:
                error = "Credenciales incorrectas. Verifique su usuario y contraseña."

    return render_template("login.html", active_page="login", error=error)


@app.route("/logout")
def logout():
    """
    Cierra la sesión activa del usuario autenticado.

    Limpia los identificadores de la cookie de sesión criptográfica y redirige
    hacia la página de inicio de sesión.
    """
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("role", None)
    session.pop("plan", None)
    return redirect(url_for("login"))


@app.route("/api/user-status")
def api_user_status():
    """
    Endpoint REST para consulta en vivo del estado de autenticación y cupo disponible.
    Permite al JavaScript cliente (main.js) actualizar en tiempo real los contadores y píldoras visuales.
    """
    user_id = session.get("user_id")
    current_user = database.get_user_by_id(user_id) if user_id else None
    is_auth = bool(current_user)
    free_count = session.get("free_usage_count", 0)
    free_left = max(0, FREE_TIER_LIMIT - free_count) if not is_auth else 999999

    return jsonify({
        "is_authenticated": is_auth,
        "user": current_user,
        "free_limit": FREE_TIER_LIMIT,
        "free_usage_count": free_count,
        "free_usage_left": free_left,
        "is_limit_reached": (free_count >= FREE_TIER_LIMIT) if not is_auth else False
    })


# ==============================================================================
# ENDPOINTS DE API REST (SERVICIOS ASÍNCRONOS CONSUMIDOS POR JAVASCRIPT)
# ==============================================================================

@app.route("/api/track-ip", methods=["POST"])
@login_required
def api_track_ip():
    """
    Endpoint REST para el análisis y geolocalización de direcciones IP.

    Ciclo de vida de la petición:
    1. Verifica si el usuario cuenta con una sesión de pago activa o si se encuentra
       en la versión de prueba gratuita. Si está en prueba gratuita y ha consumido los
       3 usos disponibles, bloquea la ejecución retornando HTTP 403 Forbidden.
    2. Recibe una solicitud HTTP POST con cuerpo JSON (o formulario URL-encoded).
    3. Extrae y limpia el parámetro 'target' (IP o FQDN).
    4. Invoca 'ip_tracker.track_ip_address(target)':
       - Valida la sintaxis (IPv4/IPv6).
       - Verifica el ámbito RFC (privada vs pública).
       - Consulta geolocalización externa si es pública.
       - Mide la latencia RTT.
    5. Si el análisis fue exitoso, persiste los datos en la tabla 'analyses'
       mediante 'database.save_ip_analysis()'.
    6. Si está en prueba gratuita, incrementa el contador de uso consumido.
    7. Adjunta el 'analysis_id' y métricas de cuota al resultado y responde con JSON HTTP 200.
    """
    # --------------------------------------------------------------------------
    # CONTROL DE ACCESO: VERIFICACIÓN DE PLAN Y LÍMITE DE PRUEBA GRATUITA
    # --------------------------------------------------------------------------
    user_id = session.get("user_id")
    current_user = database.get_user_by_id(user_id) if user_id else None
    is_auth = bool(current_user)

    if not is_auth:
        usage_count = session.get("free_usage_count", 0)
        if usage_count >= FREE_TIER_LIMIT:
            return jsonify({
                "success": False,
                "limit_reached": True,
                "error": f"Has alcanzado el límite de {FREE_TIER_LIMIT} análisis de la Prueba Gratuita. Inicia sesión con tu cuenta de pago (admin / admin) para disfrutar de análisis ilimitados.",
                "free_limit": FREE_TIER_LIMIT,
                "free_usage_count": usage_count,
                "free_usage_left": 0
            }), 403

    data = request.get_json(silent=True) or request.form
    target = data.get("target", "").strip()

    if not target:
        return jsonify({
            "success": False,
            "error": "Debe especificar una dirección IP o nombre de dominio."
        }), 400

    # En un servidor público no se permiten IP privadas, loopback ni rangos especiales.
    target_ok, resolved_ip, target_error = validate_public_target(target)
    if not target_ok:
        return jsonify({"success": False, "error": target_error}), 400

    # Ejecución de la lógica en el módulo especializado
    analysis_res = ip_tracker.track_ip_address(resolved_ip)
    if not analysis_res.get("success"):
        return jsonify(analysis_res), 400

    # Persistencia relacional en base de datos
    try:
        analysis_id = database.save_ip_analysis(analysis_res)
        analysis_res["analysis_id"] = analysis_id
    except Exception as db_err:
        # Si la base de datos falla, no se interrumpe la respuesta al usuario pero se notifica
        analysis_res["db_warning"] = f"No se pudo persistir en base de datos: {str(db_err)}"

    # Evaluación defensiva preliminar de vulnerabilidades a nivel de red y host
    try:
        analysis_res["vulnerabilities"] = vuln_scanner.evaluate_vulnerabilities(
            ip_analysis=analysis_res,
            port_scan=None
        )
    except Exception as vuln_err:
        analysis_res["vulnerabilities"] = {
            "total_vulns": 0,
            "risk_score": 0.0,
            "risk_level": "BAJO",
            "vulnerabilities": [],
            "summary": f"Aviso de escaneo: {str(vuln_err)}"
        }

    # --------------------------------------------------------------------------
    # CONTABILIZACIÓN DE USO PARA USUARIOS EN PRUEBA GRATUITA
    # --------------------------------------------------------------------------
    if not is_auth:
        session["free_usage_count"] = session.get("free_usage_count", 0) + 1
        analysis_res["is_authenticated"] = False
        analysis_res["free_limit"] = FREE_TIER_LIMIT
        analysis_res["free_usage_count"] = session["free_usage_count"]
        analysis_res["free_usage_left"] = max(0, FREE_TIER_LIMIT - session["free_usage_count"])
    else:
        analysis_res["is_authenticated"] = True
        analysis_res["free_usage_left"] = 999999

    return jsonify(analysis_res)


@app.route("/api/scan-ports", methods=["POST"])
@login_required
def api_scan_ports():
    """
    Endpoint REST para el escaneo concurrente de puertos TCP.

    Ciclo de vida de la petición:
    1. Verifica la cuota de uso si el usuario opera en modo de prueba gratuita.
       Si el escaneo se ejecuta de forma independiente (sin un 'analysis_id' previo)
       y ya consumió el límite de 3 usos, retorna HTTP 403 Forbidden.
    2. Recibe 'target', 'ports' y 'analysis_id' (opcional) en el cuerpo JSON.
    3. Parsea y valida los puertos solicitados (números individuales o rangos como '8000-8010').
    4. Si no se especificaron puertos, aplica por defecto el perfil 'essential'.
    5. Resuelve el host objetivo a IP canónica.
    6. Ejecuta el sondeo multihilo con 'port_scanner.execute_port_scan()'.
    7. Registra transaccionalmente la sesión y el detalle en las tablas
       'port_scans' y 'port_results' mediante 'database.save_port_scan()'.
    8. Retorna el resumen y desglose de puertos en JSON HTTP 200.
    """
    data = request.get_json(silent=True) or request.form
    target = data.get("target", "").strip()
    ports_input = data.get("ports")
    analysis_id = data.get("analysis_id")

    # --------------------------------------------------------------------------
    # CONTROL DE ACCESO: VERIFICACIÓN DE PLAN Y LÍMITE DE PRUEBA GRATUITA
    # --------------------------------------------------------------------------
    user_id = session.get("user_id")
    current_user = database.get_user_by_id(user_id) if user_id else None
    is_auth = bool(current_user)

    # Si el usuario NO está autenticado y ejecuta un escaneo aislado sin haber hecho track-ip previo:
    if not is_auth and not analysis_id:
        usage_count = session.get("free_usage_count", 0)
        if usage_count >= FREE_TIER_LIMIT:
            return jsonify({
                "success": False,
                "limit_reached": True,
                "error": f"Has alcanzado el límite de {FREE_TIER_LIMIT} análisis de la Prueba Gratuita. Inicia sesión con tu cuenta de pago (admin / admin) para disfrutar de análisis ilimitados.",
                "free_limit": FREE_TIER_LIMIT,
                "free_usage_count": usage_count,
                "free_usage_left": 0
            }), 403

    if not target:
        return jsonify({
            "success": False,
            "error": "Debe proporcionar el objetivo para el escaneo."
        }), 400

    # Procesamiento flexible del listado de puertos
    ports_to_scan = []
    if isinstance(ports_input, list):
        ports_to_scan = [int(p) for p in ports_input if str(p).isdigit()]
    elif isinstance(ports_input, str):
        # Admite listas separadas por coma y rangos con guion (ej. '80, 443, 8080-8085')
        for chunk in ports_input.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                parts = chunk.split("-")
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    p_start, p_end = int(parts[0]), int(parts[1])
                    # Limita los rangos continuos a un máximo prudente de 50 puertos
                    if p_start <= p_end and (p_end - p_start) <= 50:
                        ports_to_scan.extend(range(p_start, p_end + 1))
            elif chunk.isdigit():
                ports_to_scan.append(int(chunk))

    # Fallback seguro: si no hay puertos válidos, usar los puertos esenciales
    if not ports_to_scan:
        ports_to_scan = port_scanner.PRESET_PORTS["essential"]

    # Validación del host y bloqueo de redes privadas/especiales en el servidor público.
    target_ok, resolved_ip, target_error = validate_public_target(target)
    if not target_ok:
        return jsonify({"success": False, "error": target_error}), 400

    # Límite efectivo de puertos, incluidos elementos individuales y rangos.
    ports_to_scan = sorted(set(p for p in ports_to_scan if 1 <= p <= 65535))
    if not ports_to_scan or len(ports_to_scan) > 100:
        return jsonify({"success": False, "error": "Selecciona entre 1 y 100 puertos válidos (1-65535)."}), 400

    # Ejecución multihilo en el módulo de escaneo
    scan_results = port_scanner.execute_port_scan(resolved_ip, ports_to_scan)

    # Persistencia relacional en base de datos
    try:
        scan_meta = {
            "analysis_id": int(analysis_id) if analysis_id else None,
            "target": target,
            "total_ports": scan_results.get("total_scanned", 0),
            "open_ports": scan_results.get("open_ports", 0),
            "closed_ports": scan_results.get("closed_ports", 0),
            "filtered_ports": scan_results.get("filtered_ports", 0),
            "duration_seconds": scan_results.get("duration_seconds", 0.0)
        }
        scan_id = database.save_port_scan(scan_meta, scan_results.get("ports", []))
        scan_results["scan_id"] = scan_id
    except Exception as db_err:
        scan_results["db_warning"] = f"No se pudo persistir el escaneo: {str(db_err)}"

    # Si es escaneo independiente (sin analysis_id) en prueba gratuita, incrementa el contador
    if not is_auth and not analysis_id:
        session["free_usage_count"] = session.get("free_usage_count", 0) + 1

    # Evaluación integral de vulnerabilidades basada en puertos abiertos y telemetría de red
    try:
        ip_data = database.get_analysis_by_id(int(analysis_id)) if analysis_id else None
        scan_results["vulnerabilities"] = vuln_scanner.evaluate_vulnerabilities(
            ip_analysis=ip_data,
            port_scan=scan_results
        )
    except Exception as vuln_err:
        scan_results["vulnerabilities"] = {
            "total_vulns": 0,
            "risk_score": 0.0,
            "risk_level": "BAJO",
            "vulnerabilities": [],
            "summary": f"Aviso de auditoría: {str(vuln_err)}"
        }

    scan_results["success"] = True
    scan_results["is_authenticated"] = is_auth
    if not is_auth:
        scan_results["free_limit"] = FREE_TIER_LIMIT
        scan_results["free_usage_count"] = session.get("free_usage_count", 0)
        scan_results["free_usage_left"] = max(0, FREE_TIER_LIMIT - session.get("free_usage_count", 0))
    else:
        scan_results["free_usage_left"] = 999999

    return jsonify(scan_results)


@app.route("/api/generate-pdf", methods=["POST"])
@login_required
def api_generate_pdf():
    """
    Endpoint REST para compilar dinámicamente el informe PDF de auditoría.

    Flujo:
    1. Recibe los datos completos del análisis IP ('analysis_data') y del escaneo ('scan_data').
    2. Llama a 'pdf_generator.generate_security_pdf()' para compilar el archivo en disco.
    3. Registra el informe en la tabla 'pdf_reports' mediante 'database.save_pdf_report()'.
    4. Devuelve la URL de descarga directa generada con 'url_for("download_report")'.
    """
    data = request.get_json(silent=True) or {}
    analysis_data = data.get("analysis_data", {})
    scan_data = data.get("scan_data")
    vulnerabilities_data = data.get("vulnerabilities_data")
    analysis_id = data.get("analysis_id")
    scan_id = data.get("scan_id")

    if not analysis_data or not analysis_data.get("ip_address"):
        return jsonify({
            "success": False,
            "error": "Datos de análisis insuficientes para compilar el informe PDF."
        }), 400

    try:
        pdf_path = pdf_generator.generate_security_pdf(
            analysis_data=analysis_data,
            scan_data=scan_data,
            vulnerabilities_data=vulnerabilities_data
        )
        filename = os.path.basename(pdf_path)

        # Registrar metadatos en la base de datos
        report_id = database.save_pdf_report(
            analysis_id=int(analysis_id) if analysis_id else None,
            scan_id=int(scan_id) if scan_id else None,
            filename=filename,
            file_path=pdf_path
        )

        return jsonify({
            "success": True,
            "report_id": report_id,
            "filename": filename,
            "download_url": url_for("download_report", report_id=report_id)
        })
    except Exception as pdf_err:
        return jsonify({
            "success": False,
            "error": f"Error generando documento PDF: {str(pdf_err)}"
        }), 500


@app.route("/reports/download/<int:report_id>", endpoint="download_report")
@login_required
def download_report(report_id):
    """
    Endpoint para la descarga binaria segura de informes PDF emitidos.

    Mecanismo de seguridad:
    1. No expone nombres de archivo ni rutas directas en la URL (utiliza un ID entero).
    2. Busca el registro en la base de datos mediante 'get_pdf_report_by_id'.
    3. Comprueba físicamente la existencia del archivo en disco con 'os.path.isfile()'.
    4. Si existe, utiliza 'send_file' con 'as_attachment=True' para forzar al navegador
       a descargarlo como archivo adjunto con su nombre original.
    """
    report = database.get_pdf_report_by_id(report_id)
    if not report:
        abort(404, description="El informe solicitado no existe en la base de datos.")

    file_path = report["file_path"]
    if not os.path.isfile(file_path):
        abort(404, description="El archivo PDF físico no fue localizado en el servidor.")

    return send_file(
        file_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=report["filename"]
    )


@app.route("/api/contact", methods=["POST"])
def api_contact():
    """
    Endpoint REST para la recepción y almacenamiento de consultas del formulario de contacto.

    Captura de telemetría de red:
    Extrae la IP real del remitente analizando la cabecera 'X-Forwarded-For'
    (en caso de proxies reversos como Nginx) o 'request.remote_addr'.
    """
    data = request.get_json(silent=True) or request.form
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip()
    subject = data.get("subject", "").strip()
    message = data.get("message", "").strip()

    if not full_name or not email or not subject or not message:
        return jsonify({
            "success": False,
            "error": "Todos los campos del formulario son obligatorios."
        }), 400

    # Detección de IP del remitente
    sender_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    if "," in sender_ip:
        sender_ip = sender_ip.split(",")[0].strip()

    try:
        msg_id = database.save_contact_message(
            full_name=full_name,
            email=email,
            subject=subject,
            message=message,
            sender_ip=sender_ip
        )
        return jsonify({
            "success": True,
            "message": "Tu mensaje ha sido registrado exitosamente en el servidor.",
            "message_id": msg_id
        })
    except Exception as err:
        return jsonify({
            "success": False,
            "error": f"Error al registrar mensaje: {str(err)}"
        }), 500


@app.route("/api/stats")
@login_required
def api_stats():
    """
    Endpoint de telemetría pública que devuelve los KPIs y estadísticas en JSON.
    Permite refrescar el Dashboard dinámicamente sin recargar la página.
    """
    return jsonify(database.get_dashboard_stats())


# ==============================================================================
# MANEJADORES DE ERRORES HTTP GLOBALES
# ==============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Captura accesos a URLs inexistentes (HTTP 404) y renderiza una vista amigable."""
    return render_template(
        "index.html",
        active_page="index",
        error_message="El recurso o página solicitada no existe."
    ), 404


@app.errorhandler(500)
def internal_error(error):
    """Captura excepciones internas no controladas (HTTP 500) evitando pantallas en blanco."""
    return render_template(
        "index.html",
        active_page="index",
        error_message="Ocurrió un error interno en el servidor."
    ), 500


# ==============================================================================
# BLOQUE DE ARRANQUE EN MODO LOCAL / DESARROLLO
# ==============================================================================
if __name__ == "__main__":
    print("==================================================================")
    print(" CIBER-ANALYZER // Plataforma de Análisis y Ciberseguridad")
    print(" Servidor iniciado en http://127.0.0.1:5000")
    print(" Presione Ctrl + C para detener el servicio.")
    print("==================================================================")
    # host='127.0.0.1' restringe el acceso al equipo local (loopback) para máxima seguridad
    # debug=True activa la recarga automática en caliente ante cambios de código
    app.run(host="127.0.0.1", port=5000, debug=False)
