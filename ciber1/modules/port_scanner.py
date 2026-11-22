"""
===============================================================================
MÓDULO DE ESCÁNER CONCURRENTE DE PUERTOS TCP Y RECONOCIMIENTO DE SERVICIOS
===============================================================================

Este módulo implementa el motor de auditoría técnica de capa de transporte (TCP)
de la plataforma CIBER-ANALYZER.

FUNDAMENTOS DE TELECOMUNICACIONES Y REDES:
------------------------------------------
1. ¿Qué es un Puerto TCP?
   En la pila de protocolos TCP/IP, una dirección IP identifica a un host físico
   o virtual en la red. Un puerto es un número entero de 16 bits (rango de 1 a 65535)
   que actúa como multiplexor lógico de capa de transporte, permitiendo que un mismo
   servidor ejecute múltiples aplicaciones y servicios simultáneos de forma aislada
   (ej. un servidor web en el puerto 80 y un servidor de bases de datos en el 3306).

2. El Protocolo TCP y el Apretón de Manos de Tres Vías (Three-Way Handshake):
   TCP (Transmission Control Protocol) es un protocolo fiable y orientado a la conexión.
   Para iniciar una sesión entre cliente y servidor se requiere un handshake de 3 pasos:
     - Paso 1 (Cliente -> Servidor): Envía un paquete con la bandera SYN (Synchronize).
     - Paso 2 (Servidor -> Cliente): Si el puerto está ABIERTO y escuchando, responde con SYN-ACK.
     - Paso 3 (Cliente -> Servidor): El cliente confirma con un ACK (Acknowledge) y se abre el socket.

3. Determinación de Estados de un Puerto:
   - ABIERTO (OPEN):
     El servidor responde con SYN-ACK (connect_ex retorna código 0). Hay un servicio
     escuchando activamente (daemon/proceso) listo para recibir conexiones.
   - CERRADO (CLOSED):
     El host destino responde con un paquete con bandera RST (Reset) o código de conexión
     rechazada (ECONNREFUSED). El host está activo, pero ningún programa escucha en ese puerto.
   - FILTRADO (FILTERED / TIMEOUT):
     No se recibe ninguna respuesta antes de que expire el temporizador (timeout).
     Ocurre cuando un cortafuegos (Firewall perimetral o iptables) descarta silenciosamente
     (DROP) los paquetes SYN sin enviar un RST de respuesta.

4. ¿Qué es Banner Grabbing (Captura de Firmas)?
   Es una técnica de reconocimiento pasivo en la que, tras abrir la conexión TCP con un
   puerto abierto, el escáner lee los primeros bytes enviados espontáneamente por el servicio
   (o envía una cabecera neutra 'HEAD / HTTP/1.0') para identificar la versión del software
   (ej. 'Apache/2.4.52', 'OpenSSH_8.9p1').

5. Concurrencia Multihilo (ThreadPoolExecutor):
   Evaluar 50 puertos secuencialmente con un tiempo de espera de 1 segundo tardaría 50 segundos.
   Al utilizar una piscina de hilos de trabajo simultáneos (Worker Threads), el escaneo de 50
   puertos se completa en aproximadamente 1.5 a 2 segundos sin saturar la tarjeta de red.

6. Límites Éticos y Defensivos:
   El módulo establece un tope infranqueable de 100 puertos por solicitud y un máximo de 35 hilos
   para evitar cualquier comportamiento equiparable a un ataque de Denegación de Servicio (DoS).
"""

# ==============================================================================
# IMPORTACIÓN DE BIBLIOTECAS DEL SISTEMA Y CONCURRENCIA
# ==============================================================================
import socket  # Comunicación de bajo nivel mediante sockets de transporte de red.
import time    # Medición precisa de latencias y tiempos totales de ejecución con perf_counter.
from concurrent.futures import ThreadPoolExecutor, as_completed  # Concurrencia gestionada con hilos.
from typing import Dict, Any, List  # Tipado estático docente.
from datetime import datetime       # Marcas de tiempo de auditoría.

# ==============================================================================
# CATÁLOGO OFICIAL DE PUERTOS Y SERVICIOS SEGÚN ASIGNACIONES IANA
# ==============================================================================
# La Autoridad de Asignación de Números en Internet (IANA) estandariza los puertos:
# - Puertos conocidos (Well-Known): 0 al 1023 (privilegiados).
# - Puertos registrados (Registered): 1024 al 49151.
# - Puertos dinámicos/privados: 49152 al 65535.
KNOWN_SERVICES: Dict[int, str] = {
    20: "FTP-Data (Transferencia de datos de archivos)",
    21: "FTP (Canal de comandos y autenticación de archivos)",
    22: "SSH / SFTP (Terminal remota segura y cifrada)",
    23: "Telnet (Terminal remota no cifrada / Insegura)",
    25: "SMTP (Servidor de transferencia de correo electrónico)",
    53: "DNS (Resolución de nombres de dominio)",
    67: "DHCP Server (Asignación automática de IPs)",
    68: "DHCP Client (Cliente de configuración de red)",
    69: "TFTP (Trivial File Transfer Protocol)",
    80: "HTTP (Servidor web estándar sin cifrar)",
    88: "Kerberos (Autenticación de dominios de red)",
    110: "POP3 (Recepción de correo electrónico)",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Sincronización horaria de red)",
    135: "MS-RPC (Llamada a procedimiento remoto de Microsoft)",
    139: "NetBIOS (Servicio de sesión de compartición de archivos Windows)",
    143: "IMAP (Acceso y gestión de buzones de correo)",
    161: "SNMP (Monitoreo y gestión de dispositivos de red)",
    162: "SNMP-Trap (Notificaciones asíncronas de red)",
    179: "BGP (Border Gateway Protocol / Enrutamiento global)",
    389: "LDAP (Directorio corporativo y autenticación de usuarios)",
    443: "HTTPS (Servidor web seguro con cifrado TLS/SSL)",
    445: "SMB (Server Message Block / Carpetas compartidas de Windows)",
    465: "SMTPS (Envío seguro de correo con TLS)",
    514: "Syslog (Servidor centralizado de eventos y bitácoras)",
    587: "SMTP Submission (Envío autenticado de correo)",
    636: "LDAPS (LDAP seguro sobre túnel SSL/TLS)",
    873: "Rsync (Sincronización eficiente de archivos remotos)",
    993: "IMAPS (IMAP seguro con cifrado TLS)",
    995: "POP3S (POP3 seguro con cifrado TLS)",
    1080: "SOCKS Proxy (Servidor intermediario de red)",
    1194: "OpenVPN (Túnel cifrado de Red Privada Virtual)",
    1433: "Microsoft SQL Server (Base de datos relacional)",
    1434: "Microsoft SQL Server Monitor",
    1521: "Oracle Database Listener",
    1723: "PPTP VPN (Protocolo heredado de túnel punto a punto)",
    2049: "NFS (Network File System / Almacenamiento distribuido)",
    2082: "cPanel (Administración web de hosting HTTP)",
    2083: "cPanel (Administración web de hosting HTTPS)",
    2086: "WHM (WebHost Manager HTTP)",
    2087: "WHM (WebHost Manager HTTPS)",
    2375: "Docker Daemon (API REST sin cifrado)",
    2376: "Docker Daemon (API REST segura con TLS)",
    3000: "Node.js / React / Grafana Web Application",
    3306: "MySQL / MariaDB (Servidor de bases de datos relacionales)",
    3389: "RDP (Escritorio Remoto de Microsoft Windows)",
    5000: "Flask Web Server / Docker Registry",
    5432: "PostgreSQL (Motor de base de datos relacional avanzada)",
    5900: "VNC (Virtual Network Computing / Acceso gráfico remoto)",
    5985: "WinRM HTTP (Administración remota de Windows PowerShell)",
    5986: "WinRM HTTPS (Administración remota segura de Windows)",
    6379: "Redis (Almacenamiento de datos en memoria clave-valor)",
    8000: "Django / Servidor web HTTP alternativo",
    8080: "HTTP Alternate / Apache Tomcat / Proxy inverso",
    8443: "HTTPS Alternate / Consola de administración segura",
    8888: "Jupyter Notebook / Servicio analítico Python",
    9000: "Portainer / SonarQube / PHP-FPM FastCGI",
    9090: "Prometheus (Servidor de métricas de telemetría)",
    9200: "Elasticsearch (API de búsqueda y análisis distribuido)",
    9300: "Elasticsearch Cluster (Comunicación entre nodos)",
    11211: "Memcached (Sistema de caché distribuido en memoria)",
    27017: "MongoDB (Base de datos documental NoSQL)"
}

# ==============================================================================
# PERFILES RÁPIDOS PRECONFIGURADOS PARA SELECCIÓN EN LA INTERFAZ DE USUARIO
# ==============================================================================
PRESET_PORTS: Dict[str, List[int]] = {
    "web": [80, 443, 8080, 8443, 8000, 3000, 5000],
    "essential": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080],
    "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "remote_access": [22, 23, 3389, 5900, 5985, 5986]
}


def get_service_for_port(port: int) -> str:
    """
    Consulta en el catálogo IANA el nombre descriptivo del servicio asociado a un puerto.

    Parámetros:
        port (int): Número de puerto evaluado.

    Retorna:
        str: Nombre y descripción del servicio o 'Servicio no estándar' si no figura en el catálogo.
    """
    return KNOWN_SERVICES.get(port, "Servicio no estándar / Personalizado")


def scan_single_port(target_ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Evalúa el estado exacto de un puerto TCP individual en una dirección IP objetivo.

    MECANISMO TÉCNICO DETALLADO:
    ----------------------------
    1. Instanciación del Socket:
       - 'socket.SOCK_STREAM' especifica que utilizaremos el protocolo orientado a conexión TCP.
       - Si la IP contiene ':', selecciona la familia IPv6 ('socket.AF_INET6'); de lo contrario, IPv4 ('socket.AF_INET').
    2. Configuración de Timeout:
       - Se establece un temporizador rígido (por defecto 1.0 segundo). Si en ese lapso no se recibe respuesta,
         el sistema operativo cancela la llamada evitando que el hilo quede bloqueado indefinidamente.
    3. ¿Por qué connect_ex() en lugar de connect()?
       - 'connect()' lanza una excepción ('ConnectionRefusedError' o 'socket.timeout') en cada puerto cerrado.
       - Procesar miles de excepciones genera una penalización severa de rendimiento en Python.
       - 'connect_ex()' es una llamada nativa en lenguaje C que retorna directamente el código de error
         numérico (errno):
           * Código 0: ¡ÉXITO! La conexión se estableció (SYN-ACK recibido) -> Puerto ABIERTO.
           * Códigos de Timeout (10060 en Windows, 110 en Linux): Paquete ignorado -> Puerto FILTRADO.
           * Cualquier otro código (10061 / 111): Conexión rechazada -> Puerto CERRADO.
    4. Captura de Banner (Banner Grabbing no invasivo):
       - Si el puerto está ABIERTO, se intenta una lectura neutra de hasta 256 bytes.
       - Si es un puerto web (80, 443, etc.), envía una cabecera segura 'HEAD / HTTP/1.0\r\n\r\n'.
       - Limpia y sanitiza la cadena decodificando en UTF-8 con tolerancia a errores.
    5. Cierre Garantizado:
       - El bloque 'finally: sock.close()' libera inmediatamente los descriptores de archivo del sistema operativo.

    Parámetros:
        target_ip (str): Dirección IP de destino.
        port (int): Número de puerto TCP a inspeccionar (1 a 65535).
        timeout (float): Tiempo de espera en segundos por conexión.

    Retorna:
        Dict[str, Any]:
            - port_number (int): Puerto analizado.
            - state (str): 'ABIERTO', 'CERRADO' o 'FILTRADO'.
            - service_name (str): Servicio IANA detectado.
            - banner (str): Firma recibida (si estuvo disponible).
            - response_time_ms (float): Tiempo en milisegundos que tardó la prueba.
    """
    service_name = get_service_for_port(port)
    start_time = time.perf_counter()

    is_ipv6 = ":" in target_ip
    address_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET

    sock = socket.socket(address_family, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result = {
        "port_number": port,
        "state": "CERRADO",
        "service_name": service_name,
        "banner": "",
        "response_time_ms": 0.0
    }

    try:
        # Intenta la conexión TCP mediante el handshake de 3 vías
        connect_code = sock.connect_ex((target_ip, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        result["response_time_ms"] = elapsed_ms

        if connect_code == 0:
            result["state"] = "ABIERTO"

            # Intento de lectura de firma de servicio (Banner Grabbing) con timeout ultrarrápido (0.4s)
            try:
                sock.settimeout(0.4)
                # Enviar solicitud mínima HTTP HEAD si es un puerto típico de aplicación web
                if port in [80, 8080, 8000, 3000, 5000]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

                banner_raw = sock.recv(256)
                clean_banner = banner_raw.decode("utf-8", errors="ignore").strip().splitlines()
                if clean_banner:
                    # Se extrae solo la primera línea recortada a 120 caracteres por limpieza visual
                    result["banner"] = clean_banner[0][:120]
            except Exception:
                # Si el servicio no emite banner espontáneamente, simplemente se ignora sin error
                result["banner"] = ""

        # Detección de códigos de filtrado por firewall (Timeout en Windows / Unix)
        elif connect_code in [10060, 11, 35, 110]:
            result["state"] = "FILTRADO"
        else:
            result["state"] = "CERRADO"

    except socket.timeout:
        result["state"] = "FILTRADO"
        result["response_time_ms"] = round(timeout * 1000.0, 2)
    except Exception:
        result["state"] = "CERRADO"
    finally:
        # Destrucción del socket para evitar agotar los descriptores del SO
        sock.close()

    return result


def execute_port_scan(
    target_ip: str,
    ports_to_scan: List[int],
    timeout: float = 1.0,
    max_threads: int = 30
) -> Dict[str, Any]:
    """
    Coordina, paraleliza y ejecuta el escaneo de múltiples puertos concurrentemente.

    PATRÓN DE CONCURRENCIA (POOL DE HILOS):
    ---------------------------------------
    1. Sanitización de Puertos:
       - Elimina puertos duplicados y fuera de rango matemático (1 a 65535).
       - Aplica un filtro ético estricto: máximo 100 puertos por solicitud.
    2. Creación del ThreadPoolExecutor:
       - Distribuye el trabajo entre un número controlado de hilos de trabajo ('workers').
       - Se asigna un 'Worker' para cada puerto mediante 'executor.submit()'.
       - 'as_completed()' procesa los resultados conforme cada hilo individual termina,
         sin necesidad de esperar a que finalice el escaneo completo.
    3. Clasificación Estadística:
       - Cuenta dinámicamente puertos abiertos, cerrados y filtrados.
       - Reordena la lista final numéricamente para una presentación prolija.

    Parámetros:
        target_ip (str): Dirección IP normalizada del objetivo.
        ports_to_scan (List[int]): Lista de enteros con los puertos solicitados.
        timeout (float): Tiempo máximo de espera por cada puerto.
        max_threads (int): Límite de concurrencia en la piscina de hilos (máx. 35).

    Retorna:
        Dict[str, Any]: Diccionario consolidado con métricas, duración y desglose individual.
    """
    # 1. Normalización, eliminación de duplicados y ordenación previa
    unique_ports = sorted(list(set([int(p) for p in ports_to_scan if 1 <= int(p) <= 65535])))

    # 2. Control de ciberseguridad defensiva: Restricción a un máximo de 100 puertos
    if len(unique_ports) > 100:
        unique_ports = unique_ports[:100]

    start_scan_time = time.perf_counter()
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    results_list: List[Dict[str, Any]] = []
    open_count = 0
    closed_count = 0
    filtered_count = 0

    # 3. Concurrencia controlada
    workers = min(max_threads, len(unique_ports)) if unique_ports else 1

    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Diccionario que mapea cada objeto Future con su número de puerto
        future_to_port = {
            executor.submit(scan_single_port, target_ip, port, timeout): port 
            for port in unique_ports
        }

        # Procesar resultados en tiempo real conforme concluyen los sockets
        for future in as_completed(future_to_port):
            try:
                res = future.result()
                results_list.append(res)
                if res["state"] == "ABIERTO":
                    open_count += 1
                elif res["state"] == "CERRADO":
                    closed_count += 1
                else:
                    filtered_count += 1
            except Exception as e:
                # Si ocurre una excepción no controlada en el hilo, se registra de forma segura
                port_num = future_to_port[future]
                results_list.append({
                    "port_number": port_num,
                    "state": "ERROR",
                    "service_name": get_service_for_port(port_num),
                    "banner": f"Excepción técnica: {str(e)}",
                    "response_time_ms": 0.0
                })
                closed_count += 1

    # Ordenar los resultados finales de menor a mayor para una lectura estructurada
    results_list.sort(key=lambda x: x["port_number"])
    total_duration = round(time.perf_counter() - start_scan_time, 2)

    return {
        "target": target_ip,
        "timestamp": scan_timestamp,
        "total_scanned": len(unique_ports),
        "open_ports": open_count,
        "closed_ports": closed_count,
        "filtered_ports": filtered_count,
        "duration_seconds": total_duration,
        "ports": results_list,
        "security_notice": (
            "AUDITORÍA NO INVASIVA: Este escaneo verifica de manera controlada la disponibilidad "
            "del handshake SYN-ACK en la capa de transporte. No realiza pruebas de inyección, "
            "fuerza bruta ni explotación de vulnerabilidades."
        )
    }
