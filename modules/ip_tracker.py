"""
===============================================================================
MÓDULO DE INTELIGENCIA DE RED, RASTREO Y GEOLOCALIZACIÓN IP (OSINT)
===============================================================================

Este módulo implementa el motor de auditoría pasiva e inteligencia de capa de red
(Open Source Intelligence - OSINT) de la plataforma CIBER-ANALYZER.

OBJETIVOS Y RESPONSABILIDADES TÉCNICAS:
--------------------------------------
1. Validación y Normalización de Entradas:
   - Admite direcciones IPv4 canónicas (RFC 791).
   - Admite direcciones IPv6 (RFC 2460 / RFC 8200).
   - Admite nombres de dominio completamente calificados (FQDN), resolviendo su IP
     mediante consultas al Sistema de Nombres de Dominio (DNS).
2. Clasificación Estricta del Ámbito de Red (Scope Classification):
   - Discrimina rangos privados de intranet (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
   - Discrimina direcciones de bucle local (Loopback RFC 1122: 127.0.0.0/8, ::1).
   - Discrimina direcciones autoconfiguradas de enlace local (APIPA RFC 3927: 169.254.0.0/16).
   - Discrimina rangos de multidifusión (Multicast RFC 5771) y experimentales IETF.
3. Principio de Ciberseguridad y Privacidad:
   - Bloqueo de peticiones externas para rangos no enrutables: Las IPs privadas o de
     loopback NO son enviadas bajo ninguna circunstancia a servicios en la nube o APIs
     externas. Esto previene la fuga involuntaria de topología interna de red y evita
     denegaciones de servicio innecesarias.
4. Geolocalización de Infraestructura Pública:
   - Para direcciones públicas globales, consulta la API REST documentada de IP-API.
   - Extrae metadatos de telecomunicaciones: País, Región, Ciudad, Coordenadas (Lat/Lon),
     Proveedor de Servicios de Internet (ISP), Sistema Autónomo (ASN) y Organización.
5. Medición de Latencia de Red (Round-Trip Time - RTT):
   - Mide el tiempo de ida y vuelta mediante la apertura no bloqueante de un socket TCP
     hacia puertos estándar de enlace (HTTP 80, HTTPS 443 o DNS 53).
6. Búsqueda de Registro DNS Inverso (PTR - Reverse DNS Lookup):
   - Consulta los registros PTR en los servidores de nombres autoritativos.
"""

# ==============================================================================
# IMPORTACIÓN DE BIBLIOTECAS DEL SISTEMA Y RED
# ==============================================================================
import ipaddress  # Biblioteca estándar para manipulación y validación formal de direcciones y redes IPv4/IPv6.
import socket     # Interfaz de bajo nivel para comunicación mediante sockets Berkeley de red (TCP/UDP, DNS).
import time       # Medición de alta precisión con temporizadores de reloj del procesador (perf_counter).
import requests   # Biblioteca HTTP estándar de facto para realizar peticiones REST sincronizadas a APIs externas.
from typing import Dict, Any, Tuple  # Tipado estático para robustez del código y claridad educativa.


def validate_and_parse_target(target: str) -> Tuple[bool, str, str, str]:
    """
    Valida, clasifica y normaliza la entrada del usuario (dirección IP o nombre de host).

    FLUJO LÓGICO PASO A PASO:
    -------------------------
    Paso 1: Elimina espacios en blanco accidentales en los extremos (.strip()).
    Paso 2: Comprueba si la cadena está vacía.
    Paso 3: Intenta instanciar 'ipaddress.ip_address(cadena)':
            - Si tiene éxito, es una dirección IP válida pura. Identifica si es IPv4 o IPv6.
    Paso 4: Si se genera un ValueError, la cadena no es una IP numérica. Se asume que es
            un nombre de dominio (ej. 'google.com' o 'scanme.nmap.org').
            - Intenta resolver el dominio a IP mediante 'socket.gethostbyname()'.
            - Si el DNS falla, captura 'socket.gaierror' (Get Address Info Error) y
              retorna un mensaje descriptivo de fallo sin provocar que la aplicación colapse.

    Parámetros:
        target (str): Cadena de texto introducida por el usuario en el formulario.

    Retorna:
        Tuple[bool, str, str, str]:
            - es_valido (bool): True si es una IP válida o un dominio resoluble.
            - ip_canonica (str): Dirección IP normalizada en texto (ej. '142.250.190.46').
            - tipo_ip (str): 'IPv4' o 'IPv6'.
            - mensaje_error (str): Causa técnica del fallo en caso de no ser válida.
    """
    cleaned_target = target.strip()
    if not cleaned_target:
        return False, "", "", "La dirección objetivo no puede estar vacía."

    # Paso 1: Verificación como IP numérica válida directa
    try:
        ip_obj = ipaddress.ip_address(cleaned_target)
        # Discrimina la versión analizando la instancia de clase generada
        tipo = "IPv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "IPv4"
        return True, str(ip_obj), tipo, ""
    except ValueError:
        # Paso 2: Si no es IP, se comprueba si es un dominio FQDN resoluble vía DNS
        try:
            # socket.gethostbyname delega la consulta al resolver DNS configurado en el SO
            resolved_ip = socket.gethostbyname(cleaned_target)
            return True, resolved_ip, "IPv4", ""
        except socket.gaierror:
            # Error común: dominio no registrado, sin conexión a Internet o error tipográfico
            return False, "", "", f"No fue posible resolver el host o la dirección IP '{cleaned_target}'. Verifique su conexión o la ortografía."
        except Exception as e:
            return False, "", "", f"Error inesperado durante la resolución DNS: {str(e)}"


def check_ip_scope(ip_str: str) -> Dict[str, Any]:
    """
    Evalúa el ámbito de enrutamiento y alcance de la dirección IP bajo las RFC de telecomunicaciones.

    FUNDAMENTOS DE REDES (ESTÁNDARES RFC):
    --------------------------------------
    - RFC 1122 (Loopback): Direcciones 127.0.0.0/8 (y ::1 en v6). El tráfico no sale de la tarjeta
      de red virtual interna del equipo local. No llega al enrutador ni a Internet.
    - RFC 1918 (Intranet Privada):
      * Clase A: 10.0.0.0 a 10.255.255.255 (prefijo /8).
      * Clase B: 172.16.0.0 a 172.31.255.255 (prefijo /12).
      * Clase C: 192.168.0.0 a 192.168.255.255 (prefijo /16).
      Estas direcciones están reservadas para hogares y empresas. Los enrutadores de la red global
      (Backbones BGP) descartan de inmediato los paquetes con estas cabeceras.
    - RFC 3927 (Link-Local / APIPA): 169.254.0.0/16 (o fe80::/10 en v6). Se asignan cuando el
      servidor DHCP no responde en la red local.
    - RFC 5771 (Multicast): 224.0.0.0 a 239.255.255.255 (Clase D). Para transmisión uno a muchos.

    Parámetros:
        ip_str (str): Cadena de la dirección IP ya normalizada.

    Retorna:
        Dict[str, Any]:
            - is_private (bool): True si es cualquier ámbito no público enrutable.
            - scope (str): Etiqueta descriptiva del ámbito detectado.
            - description (str): Explicación técnica de la norma y su comportamiento en Internet.
            - is_loopback (bool): Si es la máquina local.
            - is_multicast (bool): Si es tráfico de grupos de multidifusión.
    """
    ip_obj = ipaddress.ip_address(ip_str)

    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_link_local = ip_obj.is_link_local
    is_multicast = ip_obj.is_multicast
    is_reserved = ip_obj.is_reserved

    if is_loopback:
        scope = "Bucle local (Loopback / Localhost)"
        description = "Dirección interna reservada para comunicación dentro del mismo sistema operativo físico (RFC 1122)."
    elif is_link_local:
        scope = "Enlace Local (Link-Local / APIPA)"
        description = "Dirección autoconfigurada no enrutable en redes de área amplia (RFC 3927)."
    elif is_private:
        scope = "Red Privada (RFC 1918)"
        description = "Dirección de intranet privada no enrutable en la Internet pública (ej. 192.168.x.x, 10.x.x.x)."
    elif is_multicast:
        scope = "Multidifusión (Multicast)"
        description = "Dirección reservada para transmisiones a grupos de hosts simultáneos (RFC 5771)."
    elif is_reserved:
        scope = "Reservada / IETF"
        description = "Rango de direcciones reservado para protocolos experimentales futuros."
    else:
        scope = "Pública Enrutable (Internet Global)"
        description = "Dirección IP pública enrutable globalmente asignada por IANA y los registros regionales (RIR)."

    # Si cumple cualquiera de estas condiciones, no debe consultarse en servicios públicos de geolocalización
    is_non_public = is_private or is_loopback or is_link_local or is_multicast or is_reserved

    return {
        "is_private": is_non_public,
        "scope": scope,
        "description": description,
        "is_loopback": is_loopback,
        "is_multicast": is_multicast
    }


def measure_latency_ms(ip_str: str, port: int = 80, timeout_sec: float = 1.5) -> float:
    """
    Mide el tiempo de ida y vuelta (Round-Trip Time - RTT) hacia el host evaluado.

    ¿POR QUÉ SE USA UN SOCKET TCP EN LUGAR DE UN PING ICMP?
    En sistemas operativos modernos (como Windows y Linux), enviar paquetes ICMP Echo Request
    (el clásico 'ping') requiere permisos de Administrador/Root (raw sockets).
    Para garantizar que la aplicación funcione en modo estándar sin privilegios elevados,
    se mide el RTT intentando una conexión TCP SYN no invasiva a puertos de transporte
    convencionales (80 HTTP, 443 HTTPS o 53 DNS).

    Parámetros:
        ip_str (str): Dirección IP destino.
        port (int): Puerto base sobre el que intentar la conexión (por defecto 80).
        timeout_sec (float): Límite de tiempo máximo para esperar la respuesta antes de abortar.

    Retorna:
        float: Tiempo de respuesta en milisegundos con 2 decimales, o -1.0 si el host no responde.
    """
    # Lista de puertos alternativos si el puerto principal no responde
    test_ports = [port, 443, 53] if port == 80 else [port]

    for p in test_ports:
        # Selección dinámica de la familia de direcciones: AF_INET para IPv4 o AF_INET6 para IPv6
        family = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)

        # 'time.perf_counter()' proporciona el reloj de mayor precisión disponible en el CPU
        start_time = time.perf_counter()
        try:
            s.connect((ip_str, p))
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            s.close()
            return round(elapsed_ms, 2)
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Si el puerto está cerrado o rechaza, el socket se destruye y prueba el siguiente puerto
            s.close()
            continue

    return -1.0


def track_ip_address(target_input: str) -> Dict[str, Any]:
    """
    Función orquestadora principal para el análisis completo de una dirección IP o dominio.

    RECORRIDO COMPLETO DEL PROCESO:
    -------------------------------
    1. Valida sintácticamente y normaliza la entrada del usuario mediante validate_and_parse_target.
    2. Determina el alcance de la dirección con check_ip_scope (pública vs privada/local).
    3. Mide la latencia de conectividad hacia el host con measure_latency_ms.
    4. Realiza una consulta de resolución inversa DNS (PTR) para obtener nombres de dominio asociados.
    5. Si el ámbito es PRIVADO o LOOPBACK:
       - Sintetiza la respuesta inmediatamente con metadatos técnicos pedagógicos.
       - NO realiza llamadas HTTP a la API externa (protege la privacidad y seguridad de la red interna).
    6. Si el ámbito es PÚBLICO:
       - Construye una petición HTTP GET segura al servicio 'http://ip-api.com/json/'.
       - Solicita campos técnicos específicos (status, país, ciudad, coordenadas, ISP, ASN, timezone).
       - Procesa la respuesta JSON y extrae la telemetría geográfica del proveedor.
    7. Añade una advertencia técnica fundamental:
       - Aclara al usuario que las coordenadas corresponden a los nodos de presencia (PoP)
         del proveedor de Internet (ISP) y no a un domicilio particular de una persona.

    Parámetros:
        target_input (str): Dirección IP (ej. '1.1.1.1') o FQDN (ej. 'cloudflare.com').

    Retorna:
        Dict[str, Any]: Estructura de diccionario completa con los resultados analíticos.
    """
    # 1. Validación sintáctica y resolución de dominio
    valid, ip_str, ip_type, err_msg = validate_and_parse_target(target_input)
    if not valid:
        return {
            "success": False,
            "error": err_msg
        }

    # 2. Análisis del ámbito de red
    scope_info = check_ip_scope(ip_str)

    # 3. Medición de latencia de transporte
    latency = measure_latency_ms(ip_str)

    # 4. Estructura base del informe resultante
    result: Dict[str, Any] = {
        "success": True,
        "input_target": target_input.strip(),
        "ip_address": ip_str,
        "ip_type": ip_type,
        "is_private": scope_info["is_private"],
        "scope_name": scope_info["scope"],
        "scope_description": scope_info["description"],
        # Si la latencia es positiva se almacena el número; de lo contrario se deja en -1.0
        "latency_ms": latency if latency > 0 else -1.0,
        "country": "No aplica (Red Local/Privada)" if scope_info["is_private"] else "Desconocido",
        "country_code": "LOC" if scope_info["is_private"] else "",
        "region": "No aplica" if scope_info["is_private"] else "Desconocido",
        "city": "No aplica" if scope_info["is_private"] else "Desconocido",
        "postal_code": "No aplica" if scope_info["is_private"] else "No disponible",
        "latitude": 0.0,
        "longitude": 0.0,
        "isp": "Red Interna / Loopback" if scope_info["is_private"] else "No disponible",
        "organization": "Entorno Local / Privado" if scope_info["is_private"] else "No disponible",
        "asn": "No asignado (Rango Privado)" if scope_info["is_private"] else "No disponible",
        "timezone": "Local" if scope_info["is_private"] else "UTC",
        "reverse_dns": "",
        "technical_notice": (
            "NOTA TÉCNICA DE CIBERSEGURIDAD: Las coordenadas geográficas y datos de ubicación "
            "corresponden exclusivamente al centro de datos, nodo de enrutamiento o Punto de Presencia (PoP) "
            "del Proveedor de Servicios de Internet (ISP). No representan la ubicación física real, "
            "domiciliaria ni la identidad personal del usuario final."
        )
    }

    # 5. Resolución inversa de DNS (PTR Record)
    # Intenta obtener el nombre canónico del host asociado a la IP consultando el árbol 'in-addr.arpa'
    try:
        reverse_name, _, _ = socket.gethostbyaddr(ip_str)
        result["reverse_dns"] = reverse_name
    except (socket.herror, socket.gaierror, OSError):
        result["reverse_dns"] = "Sin registro PTR inverso"

    # 6. Gestión de rangos privados (Aislamiento de seguridad)
    if scope_info["is_private"]:
        result["notes"] = (
            f"La dirección {ip_str} pertenece a un espacio no enrutable en Internet ({scope_info['scope']}). "
            "Siguiendo las recomendaciones de ciberseguridad, no se emiten consultas externas para salvaguardar "
            "la confidencialidad de la red interna."
        )
        return result

    # 7. Consulta a API REST externa de geolocalización (Solo para IPs Públicas)
    # Se filtran únicamente los campos necesarios mediante el parámetro 'fields'
    api_url = (
        f"http://ip-api.com/json/{ip_str}?"
        "fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    )

    try:
        # Se establece un timeout estricto de 4.0 segundos para evitar que la aplicación quede bloqueada
        # si el servicio externo experimenta alta latencia o caídas
        response = requests.get(api_url, timeout=4.0)

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result["country"] = data.get("country", "Desconocido")
                result["country_code"] = data.get("countryCode", "")
                result["region"] = data.get("regionName", "Desconocido")
                result["city"] = data.get("city", "Desconocido")
                result["postal_code"] = data.get("zip", "No disponible")
                result["latitude"] = float(data.get("lat", 0.0))
                result["longitude"] = float(data.get("lon", 0.0))
                result["isp"] = data.get("isp", "No disponible")
                result["organization"] = data.get("org", "No disponible")
                result["asn"] = data.get("as", "No disponible")
                result["timezone"] = data.get("timezone", "UTC")
            else:
                result["notes"] = f"El proveedor de datos reportó: {data.get('message', 'Sin información')}"
        else:
            result["notes"] = f"Respuesta no satisfactoria del proveedor de geolocalización (HTTP {response.status_code})."

    except requests.exceptions.Timeout:
        result["notes"] = "Tiempo de espera agotado al consultar la API externa de geolocalización IP."
    except requests.exceptions.RequestException as req_err:
        result["notes"] = f"Fallo en la comunicación con el servicio de geolocalización: {str(req_err)}"

    return result
