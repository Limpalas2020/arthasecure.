"""
===============================================================================
MÓDULO DE GESTIÓN Y PERSISTENCIA DE BASE DE DATOS RELACIONAL (SQLite 3)
===============================================================================

Este módulo representa la 'Capa de Acceso a Datos' (Data Access Layer - DAL)
de la plataforma CIBER-ANALYZER. Centraliza todas las interacciones con el motor
de base de datos relacional SQLite 3:

RESPONSABILIDADES TÉCNICAS:
--------------------------
1. Inicialización del esquema relacional (DDL: Tablas, Relaciones e Índices).
2. Provisión de conexiones seguras mediante el gestor de contexto de Python.
3. Habilitación de restricciones de integridad referencial (Foreign Keys).
4. Persistencia transaccional de análisis de IPs, escaneos de puertos y reportes.
5. Inserción de mensajes enviados desde el formulario de contacto web.
6. Agregación y consolidación de métricas analíticas (KPIs) para el Dashboard.

PRINCIPIOS DE CIBERSEGURIDAD APLICADOS:
--------------------------------------
- Protección contra Inyección SQL (SQL Injection):
  Absolutamente NINGUNA consulta SQL concatena variables directas mediante
  cadenas de formato f-strings o el operador '+'. Se emplean de forma estricta
  consultas preparadas con marcadores de posición posicionales ('?'), delegando
  la sanitización y tipado al compilador nativo de SQLite.
- Integridad de Datos:
  Se configuran claves foráneas con reglas de eliminación 'ON DELETE CASCADE'
  y 'ON DELETE SET NULL' para evitar la persistencia de registros huérfanos.
"""

# ==============================================================================
# IMPORTACIÓN DE BIBLIOTECAS DEL SISTEMA Y TIPADO
# ==============================================================================
import sqlite3  # Motor de base de datos relacional embebido estándar de Python. No requiere servidor externo.
import os       # Módulo para interactuar con el sistema de archivos del sistema operativo (rutas absolutas).
from datetime import datetime  # Para registrar marcas de tiempo canónicas (timestamps) en formato ISO/SQL.
from typing import Dict, Any, List, Optional  # Anotaciones de tipos para verificación estática y claridad docente.
from werkzeug.security import generate_password_hash, check_password_hash  # Hashing criptográfico seguro para contraseñas.

# ==============================================================================
# CONFIGURACIÓN DE RUTA ABSOLUTA DE LA BASE DE DATOS
# ==============================================================================
# Se calcula la ruta absoluta hacia el archivo 'ciber_analysis.db' ubicado en la raíz del proyecto.
# ¿Por qué se utiliza 'os.path.abspath' y 'os.path.join' con '__file__'?
# Si usáramos una ruta relativa como 'ciber_analysis.db', la base de datos se crearía en la carpeta
# desde donde el usuario ejecutó la terminal (por ejemplo, en C:\Windows\System32 si se ejecuta
# como Administrador). Usar '__file__' garantiza que la BD siempre resida en la carpeta del proyecto.
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ciber_analysis.db"))


def get_db_connection() -> sqlite3.Connection:
    """
    Establece, configura y retorna una conexión activa a la base de datos SQLite.

    Configuraciones técnicas avanzadas:
    1. row_factory = sqlite3.Row:
       Por defecto, SQLite retorna las filas como tuplas (ej. ('127.0.0.1', 'IPv4')).
       Al establecer 'sqlite3.Row', los resultados se comportan como diccionarios,
       permitiendo acceder a los campos por su nombre de columna (ej. row['ip_address']),
       lo que facilita enormemente la serialización a JSON y la lectura de código.
    2. PRAGMA foreign_keys = ON:
       Por motivos históricos de retrocompatibilidad, SQLite tiene desactivada por
       defecto la verificación de claves foráneas. Al activarla explícitamente en cada
       conexión, el motor garantiza la integridad referencial entre tablas.

    Retorna:
        sqlite3.Connection: Objeto de conexión listo para interactuar con la base de datos.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """
    Inicializa el esquema relacional de la base de datos creando las 5 tablas maestras
    y sus respectivos índices de optimización si no existen previamente.

    Esta función se ejecuta al momento de arrancar la aplicación Flask (en app.py).
    Utiliza sentencias DDL idempotentes ('CREATE TABLE IF NOT EXISTS') para evitar
    sobreescribir datos existentes en arranques posteriores.

    ESTRUCTURA DE TABLAS:
    --------------------
    1. analyses: Almacena telemetría de direccionamiento IP y geolocalización OSINT.
    2. port_scans: Sesiones generales de auditoría de puertos TCP.
    3. port_results: Detalle atómico puerto por puerto para cada sesión de escaneo.
    4. pdf_reports: Catálogo de documentos PDF generados físicamente en disco.
    5. contact_messages: Registro de consultas enviadas desde el formulario web.
    """
    # El uso de 'with get_db_connection() as conn' implementa el patrón Context Manager:
    # Si ocurre un error, SQLite hace un ROLLBACK automático; si todo termina bien, hace COMMIT.
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # ----------------------------------------------------------------------
        # TABLA 1: ANALYSES (Auditoría de Capa de Red - IP)
        # ----------------------------------------------------------------------
        # Clave primaria: id (autonumérico secuencial generado por SQLite).
        # Columnas críticas:
        # - ip_address: Dirección evaluada (ej. '8.8.8.8').
        # - ip_type: Clasificación de protocolo ('IPv4' o 'IPv6').
        # - is_private: Bandera booleana (0 = Pública, 1 = Privada RFC 1918 / Loopback).
        # - country, region, city, lat, lon: Telemetría geográfica aproximada del ISP.
        # - isp, organization, asn: Datos corporativos del Sistema Autónomo BGP.
        # - latency_ms: Tiempo de ida y vuelta (RTT) en milisegundos (-1 si no hubo respuesta).
        # - created_at: Marca temporal de creación del registro.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                ip_type TEXT NOT NULL,
                is_private INTEGER NOT NULL DEFAULT 0,
                country TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                isp TEXT,
                organization TEXT,
                asn TEXT,
                timezone TEXT,
                latency_ms REAL,
                created_at TEXT NOT NULL
            );
        """)

        # ----------------------------------------------------------------------
        # TABLA 2: PORT_SCANS (Sesiones de Auditoría de Puertos)
        # ----------------------------------------------------------------------
        # Representa el resumen consolidado de un sondeo TCP sobre un host específico.
        # Clave foránea: analysis_id referenciando a analyses(id).
        # Regla: ON DELETE SET NULL (si se elimina la IP analizada, el historial del
        # escaneo se conserva conservando la evidencia del diagnóstico de red).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                target TEXT NOT NULL,
                total_ports INTEGER NOT NULL DEFAULT 0,
                open_ports INTEGER NOT NULL DEFAULT 0,
                closed_ports INTEGER NOT NULL DEFAULT 0,
                filtered_ports INTEGER NOT NULL DEFAULT 0,
                duration_seconds REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE SET NULL
            );
        """)

        # ----------------------------------------------------------------------
        # TABLA 3: PORT_RESULTS (Resultados Detallados Puerto por Puerto)
        # ----------------------------------------------------------------------
        # Almacena el resultado individual de cada puerto evaluado en una sesión.
        # Clave foránea: scan_id referenciando a port_scans(id).
        # Regla: ON DELETE CASCADE (si se borra la sesión de escaneo, todos los
        # registros individuales de puertos asociados se eliminan en cascada).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port_number INTEGER NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                banner TEXT,
                response_time_ms REAL,
                FOREIGN KEY (scan_id) REFERENCES port_scans(id) ON DELETE CASCADE
            );
        """)

        # ----------------------------------------------------------------------
        # TABLA 4: PDF_REPORTS (Catálogo de Documentos de Auditoría Emitidos)
        # ----------------------------------------------------------------------
        # Registra la metadata de cada informe PDF generado físicamente en disco.
        # Claves foráneas hacia analyses(id) y port_scans(id).
        # Mantiene un contador incremental atómico 'download_count'.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pdf_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                scan_id INTEGER,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                download_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                FOREIGN KEY (scan_id) REFERENCES port_scans(id) ON DELETE SET NULL
            );
        """)

        # ----------------------------------------------------------------------
        # TABLA 5: CONTACT_MESSAGES (Buzón del Formulario de Contacto)
        # ----------------------------------------------------------------------
        # Almacena de forma persistente los mensajes remitidos por los usuarios.
        # Registra la IP de origen (sender_ip) para trazabilidad técnica.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                sender_ip TEXT,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
            );
        """)

        # ----------------------------------------------------------------------
        # TABLA 6: USERS (Usuarios y Control de Acceso por Roles y Planes de Pago)
        # ----------------------------------------------------------------------
        # Almacena las cuentas de usuario registradas con acceso ilimitado / de pago.
        # SEGURIDAD CRIPTOGRÁFICA:
        # Nunca se almacena texto plano en 'password_hash'. Se utiliza el algoritmo
        # de derivación de claves PBKDF2:SHA256 con sal aleatoria (salt) mediante
        # Werkzeug Security, protegiendo las credenciales contra ataques de tablas arcoíris.
        # Columnas:
        # - id: Identificador único autoincremental (Clave primaria).
        # - username: Nombre de usuario único (ej. 'admin').
        # - password_hash: Hash criptográfico seguro de la contraseña.
        # - role: Rol de autorización ('admin', 'analyst', 'member').
        # - plan: Plan de suscripción ('unlimited', 'enterprise', 'free').
        # - created_at: Marca de tiempo de registro en el sistema.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                plan TEXT NOT NULL DEFAULT 'unlimited',
                created_at TEXT NOT NULL
            );
        """)

        # ----------------------------------------------------------------------
        # ÍNDICES B-TREE (Optimización de Consultas Frecuentes)
        # ----------------------------------------------------------------------
        # Los índices aceleran exponencialmente las búsquedas SELECT WHERE y los
        # JOINs evitando escaneos secuenciales de tabla completa (Full Table Scans).
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_ip ON analyses(ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_date ON analyses(created_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON port_scans(target);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_results_scan ON port_results(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        # ----------------------------------------------------------------------
        # SEMILLA DE USUARIO ADMINISTRADOR POR DEFECTO (admin / admin)
        # ----------------------------------------------------------------------
        # Se verifica si ya existe el usuario 'admin' en la tabla 'users'. Si no existe,
        # se crea de forma automática con rol 'admin', plan 'unlimited' y la contraseña
        # 'admin' debidamente hasheada para habilitar el acceso de pago ilimitado.
        cursor.execute("SELECT id FROM users WHERE username = ?;", ("admin",))
        existing_admin = cursor.fetchone()
        if not existing_admin:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            hashed_pw = generate_password_hash("admin")
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, plan, created_at)
                VALUES (?, ?, ?, ?, ?);
            """, ("admin", hashed_pw, "admin", "unlimited", now_str))

        conn.commit()


def save_ip_analysis(analysis_data: Dict[str, Any]) -> int:
    """
    Inserta un nuevo registro de rastreo y geolocalización de dirección IP en la BD.

    Manejo de robustez de tipos:
    El campo 'latency_ms' puede provenir del módulo ip_tracker como float o como
    texto descriptivo en caso de filtrado. Esta función normaliza cualquier valor
    no numérico a '-1.0' para salvaguardar la coherencia de la columna REAL de SQLite
    y evitar errores de comparación en el motor de plantillas Jinja2.

    Parámetros:
        analysis_data (Dict[str, Any]): Diccionario estructurado generado por ip_tracker.py.

    Retorna:
        int: Identificador autonumérico (id) del registro recién insertado en la tabla analyses.
    """
    # 1. Normalización segura de latencia a valor flotante (REAL)
    raw_lat = analysis_data.get("latency_ms", 0.0)
    try:
        lat_val = float(raw_lat)
    except (ValueError, TypeError):
        lat_val = -1.0

    # 2. Obtener marca de tiempo canónica del sistema
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 3. Inserción con sentencia SQL parametrizada anti-inyección
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (
                ip_address, ip_type, is_private, country, region, city,
                latitude, longitude, isp, organization, asn, timezone,
                latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            analysis_data.get("ip_address"),
            analysis_data.get("ip_type", "IPv4"),
            1 if analysis_data.get("is_private") else 0,
            analysis_data.get("country", "Desconocido"),
            analysis_data.get("region", "Desconocido"),
            analysis_data.get("city", "Desconocido"),
            analysis_data.get("latitude", 0.0),
            analysis_data.get("longitude", 0.0),
            analysis_data.get("isp", "No disponible"),
            analysis_data.get("organization", "No disponible"),
            analysis_data.get("asn", "No disponible"),
            analysis_data.get("timezone", "UTC"),
            lat_val,
            now
        ))
        conn.commit()
        # Retorna el ROWID generado automáticamente por SQLite
        return cursor.lastrowid


def save_port_scan(scan_meta: Dict[str, Any], ports_results: List[Dict[str, Any]]) -> int:
    """
    Registra de forma transaccional una sesión de escaneo de puertos (cabecera)
    y cada uno de los puertos evaluados individualmente (detalle 1 a N).

    Manejo Transaccional ACID:
    Tanto la cabecera (port_scans) como los registros individuales (port_results)
    se ejecutan dentro del mismo bloque de conexión. Si la inserción de algún puerto
    falla, la transacción completa se revierte impidiendo datos inconsistentes.

    Parámetros:
        scan_meta (Dict[str, Any]): Resumen del escaneo (target, total, abiertos, cerrados, duración).
        ports_results (List[Dict[str, Any]]): Lista de diccionarios con el detalle de cada puerto TCP.

    Retorna:
        int: Identificador (scan_id) de la sesión de escaneo registrada.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Inserción de la sesión maestra
        cursor.execute("""
            INSERT INTO port_scans (
                analysis_id, target, total_ports, open_ports, closed_ports,
                filtered_ports, duration_seconds, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            scan_meta.get("analysis_id"),
            scan_meta.get("target"),
            scan_meta.get("total_ports", 0),
            scan_meta.get("open_ports", 0),
            scan_meta.get("closed_ports", 0),
            scan_meta.get("filtered_ports", 0),
            scan_meta.get("duration_seconds", 0.0),
            now
        ))
        scan_id = cursor.lastrowid

        # Inserción en lote de los resultados atómicos por puerto
        for pr in ports_results:
            cursor.execute("""
                INSERT INTO port_results (
                    scan_id, port_number, state, service_name, banner, response_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (
                scan_id,
                pr.get("port_number"),
                pr.get("state"),
                pr.get("service_name", "Desconocido"),
                pr.get("banner", ""),
                pr.get("response_time_ms", 0.0)
            ))

        conn.commit()
        return scan_id


def save_pdf_report(analysis_id: Optional[int], scan_id: Optional[int], filename: str, file_path: str) -> int:
    """
    Registra en la base de datos la emisión exitosa de un informe técnico en PDF.

    Parámetros:
        analysis_id (int, opcional): ID del análisis IP asociado (o None si no aplica).
        scan_id (int, opcional): ID de la sesión de escaneo asociada (o None).
        filename (str): Nombre amigable del archivo (ej. 'Reporte_Seguridad_8_8_8_8_20261119.pdf').
        file_path (str): Ruta absoluta en el disco del servidor donde se guardó físicamente el PDF.

    Retorna:
        int: ID autonumérico del informe en la tabla pdf_reports.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pdf_reports (
                analysis_id, scan_id, filename, file_path, download_count, created_at
            ) VALUES (?, ?, ?, ?, 0, ?);
        """, (analysis_id, scan_id, filename, file_path, now))
        conn.commit()
        return cursor.lastrowid


def get_pdf_report_by_id(report_id: int) -> Optional[Dict[str, Any]]:
    """
    Busca los metadatos de un informe PDF por su clave primaria y actualiza
    de forma atómica el contador de descargas (+1).

    Parámetros:
        report_id (int): Identificador del reporte solicitado para descarga.

    Retorna:
        Optional[Dict[str, Any]]: Diccionario con las columnas del reporte o None si no existe.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pdf_reports WHERE id = ?;", (report_id,))
        row = cursor.fetchone()
        if not row:
            return None

        # Incremento atómico del contador de descargas
        cursor.execute("UPDATE pdf_reports SET download_count = download_count + 1 WHERE id = ?;", (report_id,))
        conn.commit()
        return dict(row)


def save_contact_message(full_name: str, email: str, subject: str, message: str, sender_ip: str = "") -> int:
    """
    Almacena en la tabla contact_messages una consulta remitida desde la interfaz web.

    Parámetros:
        full_name (str): Nombre completo del usuario remitente.
        email (str): Dirección de correo electrónico de contacto.
        subject (str): Asunto o título de la consulta.
        message (str): Cuerpo textual del mensaje.
        sender_ip (str): Dirección IP de origen detectada por Flask en la cabecera HTTP.

    Retorna:
        int: Identificador del mensaje registrado.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO contact_messages (
                full_name, email, subject, message, sender_ip, created_at, is_read
            ) VALUES (?, ?, ?, ?, ?, ?, 0);
        """, (full_name, email, subject, message, sender_ip, now))
        conn.commit()
        return cursor.lastrowid


def get_dashboard_stats() -> Dict[str, Any]:
    """
    Ejecuta consultas analíticas y funciones de agregación SQL (COUNT, SUM, GROUP BY)
    para consolidar la telemetría histórica del sistema que alimenta el Dashboard interactivo.

    Consultas ejecutadas:
    1. Conteo total de direcciones IP analizadas históricamente.
    2. Conteo de sesiones de escaneo ejecutadas.
    3. Sumas acumuladas de puertos detectados en estado abierto, cerrado y filtrado.
    4. Distribución porcentual por versión de protocolo de red (IPv4 vs IPv6).
    5. Top 5 servicios abiertos más recurrentes (filtrados del catálogo IANA).
    6. Top 5 países con mayor número de IPs georreferenciadas.
    7. Las últimas 8 consultas de IPs para la tabla de actividad reciente.
    8. Los últimos 6 escaneos de puertos ejecutados.
    9. Total de reportes PDF emitidos.

    Retorna:
        Dict[str, Any]: Estructura anidada con 'kpis', 'charts', 'recent_analyses' y 'recent_scans'.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. KPI: Total de IPs analizadas
        cursor.execute("SELECT COUNT(*) AS total FROM analyses;")
        total_ips = cursor.fetchone()["total"]

        # 2. KPI: Total de sesiones de escaneo de puertos
        cursor.execute("SELECT COUNT(*) AS total FROM port_scans;")
        total_scans = cursor.fetchone()["total"]

        # 3. KPIs: Sumatoria global de puertos abiertos, cerrados y filtrados
        # COALESCE convierte NULL a 0 cuando la base de datos se encuentra vacía.
        cursor.execute("""
            SELECT 
                COALESCE(SUM(open_ports), 0) AS total_open,
                COALESCE(SUM(closed_ports), 0) AS total_closed,
                COALESCE(SUM(filtered_ports), 0) AS total_filtered
            FROM port_scans;
        """)
        port_counts = cursor.fetchone()
        total_open_ports = port_counts["total_open"]
        total_closed_ports = port_counts["total_closed"]
        total_filtered_ports = port_counts["total_filtered"]

        # 4. Gráfico: Agrupación por protocolo IP (IPv4 vs IPv6)
        cursor.execute("""
            SELECT ip_type, COUNT(*) AS count 
            FROM analyses 
            GROUP BY ip_type;
        """)
        ip_types = {row["ip_type"]: row["count"] for row in cursor.fetchall()}

        # 5. Gráfico: Top 5 de servicios abiertos más frecuentes
        cursor.execute("""
            SELECT service_name, COUNT(*) AS count
            FROM port_results
            WHERE state = 'ABIERTO' AND service_name IS NOT NULL AND service_name != 'Desconocido'
            GROUP BY service_name
            ORDER BY count DESC
            LIMIT 5;
        """)
        top_services = [{"service": row["service_name"], "count": row["count"]} for row in cursor.fetchall()]

        # 6. Gráfico: Top 5 de países con mayor presencia en análisis
        cursor.execute("""
            SELECT country, COUNT(*) AS count
            FROM analyses
            WHERE country IS NOT NULL AND country != 'Desconocido' AND country != 'No aplica (Red Local/Privada)'
            GROUP BY country
            ORDER BY count DESC
            LIMIT 5;
        """)
        top_countries = [{"country": row["country"], "count": row["count"]} for row in cursor.fetchall()]

        # 7. Tabla Reciente: Últimas 8 consultas de IPs realizadas
        cursor.execute("""
            SELECT id, ip_address, ip_type, is_private, country, city, isp, latency_ms, created_at
            FROM analyses
            ORDER BY id DESC
            LIMIT 8;
        """)
        recent_analyses = []
        for row in cursor.fetchall():
            item = dict(row)
            # Asegura la consistencia numérica de latencia para las condiciones en Jinja2
            try:
                item["latency_ms"] = float(item.get("latency_ms", -1.0))
            except (ValueError, TypeError):
                item["latency_ms"] = -1.0
            recent_analyses.append(item)

        # 8. Tabla Reciente: Últimos 6 escaneos de puertos
        cursor.execute("""
            SELECT id, target, total_ports, open_ports, closed_ports, duration_seconds, created_at
            FROM port_scans
            ORDER BY id DESC
            LIMIT 6;
        """)
        recent_scans = [dict(row) for row in cursor.fetchall()]

        # 9. KPI: Total de reportes PDF creados
        cursor.execute("SELECT COUNT(*) AS total FROM pdf_reports;")
        total_reports = cursor.fetchone()["total"]

        return {
            "kpis": {
                "total_ips": total_ips,
                "total_scans": total_scans,
                "total_open_ports": total_open_ports,
                "total_closed_ports": total_closed_ports,
                "total_filtered_ports": total_filtered_ports,
                "total_reports": total_reports
            },
            "charts": {
                "ip_types": ip_types,
                "ports_distribution": {
                    "abiertos": total_open_ports,
                    "cerrados": total_closed_ports,
                    "filtrados": total_filtered_ports
                },
                "top_services": top_services,
                "top_countries": top_countries
            },
            "recent_analyses": recent_analyses,
            "recent_scans": recent_scans
        }


def get_analysis_by_id(analysis_id: int) -> Optional[Dict[str, Any]]:
    """
    Recupera el detalle completo de un registro de análisis IP por su ID primario.

    Parámetros:
        analysis_id (int): Identificador en la tabla analyses.

    Retorna:
        Optional[Dict[str, Any]]: Registro serializado como diccionario o None si no existe.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE id = ?;", (analysis_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Recupera la cabecera de un escaneo de puertos y ejecuta un JOIN lógico
    recuperando la lista ordenada de todos los puertos evaluados en dicha sesión.

    Parámetros:
        scan_id (int): Identificador de la sesión en la tabla port_scans.

    Retorna:
        Optional[Dict[str, Any]]: Diccionario del escaneo con la lista 'ports' anidada.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM port_scans WHERE id = ?;", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        scan_data = dict(scan_row)
        cursor.execute("SELECT * FROM port_results WHERE scan_id = ? ORDER BY port_number ASC;", (scan_id,))
        scan_data["ports"] = [dict(r) for r in cursor.fetchall()]
        return scan_data


def get_all_reports() -> List[Dict[str, Any]]:
    """
    Obtiene la lista cronológica descendente de todos los reportes PDF emitidos,
    vinculando mediante un LEFT JOIN la dirección IP, país e ISP del análisis asociado.

    ¿Por qué LEFT JOIN?
    Si un informe PDF fue emitido solo con datos de escaneo de puertos y sin un análisis
    IP asociado (o si el análisis IP fue borrado), el LEFT JOIN garantiza que el reporte
    PDF siga apareciendo en la lista en lugar de desaparecer como ocurriría con un INNER JOIN.

    Retorna:
        List[Dict[str, Any]]: Lista de registros de reportes listos para mostrar en la interfaz.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.id, r.filename, r.file_path, r.download_count, r.created_at,
                   a.ip_address, a.country, a.isp
            FROM pdf_reports r
            LEFT JOIN analyses a ON r.analysis_id = a.id
            ORDER BY r.id DESC;
        """)
        return [dict(row) for row in cursor.fetchall()]


# ==============================================================================
# GESTIÓN Y AUTENTICACIÓN DE USUARIOS (SISTEMA DE ACCESO Y PLANES DE PAGO)
# ==============================================================================

def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Verifica las credenciales de inicio de sesión de un usuario contra la base de datos.

    FLUJO DE SEGURIDAD CRIPTOGRÁFICA:
    1. Busca al usuario por su nombre de usuario ('username') usando una consulta parametrizada
       para prevenir Inyección SQL: 'SELECT * FROM users WHERE username = ?;'.
    2. Si el usuario no existe, retorna None de inmediato.
    3. Si el usuario existe, extrae el hash almacenado en 'password_hash'.
    4. Invoca 'check_password_hash(hash, password)' de Werkzeug. Esta función aplica
       el mismo algoritmo de sal y derivación criptográfica para validar si la contraseña
       en texto plano coincide con el resumen hash sin desencriptarlo (las funciones hash
       son unidireccionales e irreversibles).
    5. Si coincide, extrae los datos del usuario en un diccionario, excluye el hash por seguridad
       y lo retorna para establecer la sesión en Flask.

    Parámetros:
        username (str): Nombre de usuario introducido en el formulario de login.
        password (str): Contraseña en texto plano introducida por el usuario.

    Retorna:
        Optional[Dict[str, Any]]: Diccionario con los datos del usuario autenticado (id, username, role, plan)
                                 o None si la autenticación falla.
    """
    if not username or not password:
        return None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?;", (username.strip(),))
        row = cursor.fetchone()

        if not row:
            return None

        # Verificación criptográfica segura resistente a ataques de temporización
        if check_password_hash(row["password_hash"], password):
            user_data = dict(row)
            # Por higiene de seguridad, eliminamos el hash antes de pasarlo al controlador web
            user_data.pop("password_hash", None)
            return user_data

        return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Recupera el perfil de un usuario a partir de su identificador primario numérico (id).

    Utilizado principalmente por el decorador o procesador de contexto de Flask
    a partir del 'user_id' persistido de forma segura en la cookie de sesión firmada.

    Parámetros:
        user_id (int): Clave primaria del usuario en la tabla 'users'.

    Retorna:
        Optional[Dict[str, Any]]: Datos del usuario (sin password_hash) o None si no existe.
    """
    if not user_id:
        return None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, plan, created_at FROM users WHERE id = ?;", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def create_user(username: str, password: str, role: str = "member", plan: str = "unlimited") -> Optional[int]:
    """
    Registra un nuevo usuario en el sistema con su contraseña hasheada y asignación de plan.

    Parámetros:
        username (str): Nombre de usuario único.
        password (str): Contraseña en texto plano a ser hasheada.
        role (str): Rol de autorización ('admin', 'analyst', 'member').
        plan (str): Plan de acceso ('unlimited', 'enterprise', 'free').

    Retorna:
        Optional[int]: ID del nuevo usuario creado, o None si el nombre de usuario ya existe.
    """
    if not username or not password:
        return None

    hashed_pw = generate_password_hash(password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, plan, created_at)
                VALUES (?, ?, ?, ?, ?);
            """, (username.strip(), hashed_pw, role, plan, now_str))
            conn.commit()
            return cursor.lastrowid
    except sqlite3.IntegrityError:
        # Falla si el nombre de usuario ya está registrado (restricción UNIQUE)
        return None
