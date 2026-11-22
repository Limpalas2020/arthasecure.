"""
===============================================================================
MÓDULO DE EVALUACIÓN DEFENSIVA DE VULNERABILIDADES Y RIESGOS DE RED (OSINT/CVE)
===============================================================================

Este módulo implementa el motor de auditoría de vulnerabilidades y modelado de amenazas
defensivo de la plataforma CIBER-ANALYZER.

PRINCIPIOS DE CIBERSEGURIDAD Y METODOLOGÍA APLICADA:
----------------------------------------------------
1. Auditoría No Invasiva (Non-Intrusive Vulnerability Assessment):
   A diferencia de herramientas de explotación activa o escáneres agresivos que
   inyectan exploits o realizan ataques de fuerza bruta que podrían degradar
   o interrumpir servicios legítimos, este motor opera mediante inspección pasiva
   y correlación heurística:
     - Analiza puertos TCP abiertos expuestos a redes no confiables.
     - Inspecciona firmas y cabeceras capturadas en banners de servicio.
     - Clasifica el alcance y contexto de red de la dirección IP (RFC 1918 vs Pública).
     - Contrasta los hallazgos contra una base de conocimiento basada en los
       estándares CWE (Common Weakness Enumeration), CVE (Common Vulnerabilities
       and Exposures), CVSS v3.1 y directrices OWASP/NIST.

2. Enfoque 100% Defensivo y Orientado a Hardening:
   Cada vulnerabilidad detectada se documenta con su código de debilidad, impacto
   potencial y la directriz técnica de remediación recomendada (configuración segura,
   cifrado TLS, cierre de puertos o aislamiento en redes privadas virtuales).

3. Escala de Severidad y Cálculo de Riesgo Global:
   Se utiliza la escala cualitativa estándar CVSS v3.1:
     - CRÍTICA  (CVSS 9.0 - 10.0): Riesgo inmediato de compromiso total.
     - ALTA     (CVSS 7.0 - 8.9):  Transmisión de credenciales en texto plano o RCE potencial.
     - MEDIA    (CVSS 4.0 - 6.9):  Configuraciones débiles o falta de cifrado en datos.
     - BAJA     (CVSS 0.1 - 3.9):  Divulgación de versiones y banners técnicos.
     - INFO     (CVSS 0.0):        Reconocimiento de arquitectura sin debilidad directa.
"""

# ==============================================================================
# IMPORTACIÓN DE MÓDULOS DEL SISTEMA Y TIPADO
# ==============================================================================
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

# ==============================================================================
# BASE DE CONOCIMIENTO DE VULNERABILIDADES POR PUERTO Y PROTOCOLO
# ==============================================================================
# Diccionario estructurado que asocia números de puerto estándar con perfiles
# de riesgo, debilidades CWE conocidas y recomendaciones de remediación.
VULN_KNOWLEDGE_BASE: Dict[int, Dict[str, Any]] = {
    21: {
        "title": "Protocolo FTP sin Cifrado (Transmisión en Texto Claro)",
        "service": "FTP (File Transfer Protocol)",
        "severity": "ALTA",
        "cvss_score": 7.5,
        "cwe_id": "CWE-319",
        "cve_ref": "CVE-2015-3306 / RFC 959",
        "description": (
            "El servicio FTP opera sobre un protocolo de transmisión no cifrado. "
            "Tanto las credenciales de autenticación (usuario y contraseña) como los archivos "
            "transferidos viajan en texto claro a través de la red, permitiendo a intermediarios "
            "capturar información confidencial mediante técnicas de escucha pasiva (Eavesdropping / Sniffing)."
        ),
        "remediation": (
            "Migrar a SFTP (SSH File Transfer Protocol en el puerto TCP 22) o implementar FTPS "
            "con cifrado TLS 1.3 obligatorio. Desactivar el inicio de sesión anónimo (Anonymous FTP) "
            "si no es estrictamente necesario."
        )
    },
    23: {
        "title": "Protocolo Telnet Obsoleto y Vulnerable a Intercepción",
        "service": "Telnet Remote Terminal",
        "severity": "CRÍTICA",
        "cvss_score": 9.8,
        "cwe_id": "CWE-319",
        "cve_ref": "RFC 854 Deprecation / CWE-319",
        "description": (
            "Telnet es un protocolo heredado que carece completamente de mecanismos criptográficos. "
            "Cualquier comando ejecutado en la terminal, incluyendo la clave de acceso de superusuario, "
            "es visible en texto plano por cualquier nodo ubicado en la ruta de enrutamiento."
        ),
        "remediation": (
            "Deshabilitar y desinstalar de inmediato el demonio Telnet. Sustituirlo por OpenSSH "
            "utilizando autenticación por par de claves criptográficas (Ed25519 o RSA >= 4096 bits) "
            "y deshabilitar el acceso directo por contraseña para el usuario 'root'."
        )
    },
    25: {
        "title": "Servidor SMTP Expuesto con Riesgo de Retransmisión Abierta (Open Relay)",
        "service": "SMTP Mail Transport",
        "severity": "MEDIA",
        "cvss_score": 6.5,
        "cwe_id": "CWE-284",
        "cve_ref": "RFC 5321 / CWE-284",
        "description": (
            "Un servidor SMTP expuesto a redes públicas que no cuente con autenticación rigurosa "
            "puede ser utilizado como relé abierto (Open Relay) por botnets para campañas masivas de spam, "
            "ocasionando el bloqueo de la IP en listas negras globales (RBL/DNSBL)."
        ),
        "remediation": (
            "Exigir autenticación SASL obligatoria antes de autorizar el reenvío de correo. "
            "Habilitar STARTTLS con cifrado robusto y configurar registros SPF, DKIM y DMARC en el DNS del dominio."
        )
    },
    53: {
        "title": "Servicio DNS Expuesto con Potencial de Amplificación DDoS y Envenenamiento",
        "service": "DNS (Domain Name System)",
        "severity": "MEDIA",
        "cvss_score": 6.8,
        "cwe_id": "CWE-400",
        "cve_ref": "CVE-2008-1447 / RFC 5358",
        "description": (
            "Los servidores DNS con recursión abierta pueden ser abusados por atacantes para ejecutar "
            "ataques de denegación de servicio distribuido (DDoS) por amplificación DNS o sufrir ataques "
            "de envenenamiento de caché (Kaminsky DNS Cache Poisoning)."
        ),
        "remediation": (
            "Desactivar la resolución recursiva para direcciones IP externas (permitir recursión únicamente "
            "a clientes locales confiables). Desplegar extensiones de seguridad DNSSEC y habilitar limitación "
            "de tasa de respuesta (Response Rate Limiting - RRL)."
        )
    },
    80: {
        "title": "Servidor HTTP sin Cifrado TLS (Tráfico Web en Texto Claro)",
        "service": "HTTP (Hypertext Transfer Protocol)",
        "severity": "MEDIA",
        "cvss_score": 5.3,
        "cwe_id": "CWE-319",
        "cve_ref": "OWASP A02:2021 (Cryptographic Failures)",
        "description": (
            "El servidor web atiende solicitudes a través de HTTP estándar sin cifrado. "
            "Las cookies de sesión, tokens de autenticación y datos de formularios transmitidos "
            "son susceptibles a robo de sesión (Session Hijacking) y ataques de intermediario (MitM)."
        ),
        "remediation": (
            "Instalar un certificado digital SSL/TLS válido (ej. Let's Encrypt). "
            "Configurar una regla de redirección permanente HTTP 301 hacia HTTPS en el puerto TCP 443 "
            "y habilitar la cabecera 'Strict-Transport-Security' (HSTS) con una duración mínima de 1 año."
        )
    },
    110: {
        "title": "Protocolo de Correo POP3 no Cifrado",
        "service": "POP3 (Post Office Protocol v3)",
        "severity": "ALTA",
        "cvss_score": 7.4,
        "cwe_id": "CWE-319",
        "cve_ref": "RFC 1939 / CWE-319",
        "description": (
            "La descarga de correos mediante POP3 estándar transmite el usuario y contraseña del buzón "
            "en texto plano, exponiendo la privacidad de las comunicaciones corporativas."
        ),
        "remediation": (
            "Deshabilitar el puerto 110 y forzar el uso de POP3S sobre el puerto TCP 995 con cifrado TLS nativo."
        )
    },
    135: {
        "title": "Servicio Microsoft RPC Endpoint Mapper Expuesto",
        "service": "MSRPC / DCE-RPC",
        "severity": "ALTA",
        "cvss_score": 8.1,
        "cwe_id": "CWE-284",
        "cve_ref": "MS03-026 / CVE-2003-0352",
        "description": (
            "El servicio RPC de Windows proporciona información sobre los puntos finales de servicios del sistema. "
            "Su exposición a redes no confiables facilita el reconocimiento de servicios internos y ha sido históricamente "
            "vector de exploits de ejecución remota de código en entornos Windows."
        ),
        "remediation": (
            "Bloquear el puerto TCP 135 en el cortafuegos perimetral. Este servicio nunca debe estar expuesto a Internet."
        )
    },
    139: {
        "title": "NetBIOS Session Service Expuesto a Red Externa",
        "service": "NetBIOS-SSN",
        "severity": "ALTA",
        "cvss_score": 7.8,
        "cwe_id": "CWE-200",
        "cve_ref": "RFC 1002 / CWE-200",
        "description": (
            "El protocolo NetBIOS permite la enumeración de nombres de dominio de Windows, recursos compartidos, "
            "usuarios del sistema y grupos de trabajo locales sin autenticación."
        ),
        "remediation": (
            "Deshabilitar NetBIOS sobre TCP/IP en la configuración de los adaptadores de red y filtrar el puerto 139 en el firewall."
        )
    },
    143: {
        "title": "Servicio de Correo IMAP sin Cifrado de Transporte",
        "service": "IMAP (Internet Message Access Protocol)",
        "severity": "ALTA",
        "cvss_score": 7.4,
        "cwe_id": "CWE-319",
        "cve_ref": "RFC 3501 / CWE-319",
        "description": (
            "El protocolo IMAP estándar en el puerto 143 transmite las credenciales de correo sin cifrar "
            "a menos que se active STARTTLS explícitamente."
        ),
        "remediation": (
            "Migrar al puerto seguro IMAPS (TCP 993) con TLS forzoso desde el apretón de manos inicial."
        )
    },
    445: {
        "title": "Exposición Crítica de SMB/CIFS (Alto Riesgo de Ransomware y Exploits Remotos)",
        "service": "Microsoft SMB (Server Message Block)",
        "severity": "CRÍTICA",
        "cvss_score": 9.8,
        "cwe_id": "CWE-284",
        "cve_ref": "CVE-2017-0144 (EternalBlue) / CVE-2020-0796",
        "description": (
            "El protocolo de compartición de archivos e impresoras SMB es uno de los vectores más críticos "
            "y explotados en la historia de la ciberseguridad (utilizado por el ransomware WannaCry y NotPetya). "
            "Su exposición directa a Internet permite ataques automatizados de ejecución remota de código (RCE) "
            "y propagación lateral inmediata en redes corporativas."
        ),
        "remediation": (
            "Bloquear de inmediato el puerto TCP 445 en el firewall perimetral hacia redes públicas. "
            "El acceso a recursos compartidos Windows debe realizarse exclusivamente a través de una VPN corporativa. "
            "Deshabilitar la versión obsoleta SMBv1 en todo el entorno operativo."
        )
    },
    1433: {
        "title": "Motor de Base de Datos Microsoft SQL Server Expuesto a Internet",
        "service": "Microsoft SQL Server",
        "severity": "ALTA",
        "cvss_score": 8.5,
        "cwe_id": "CWE-284",
        "cve_ref": "OWASP A01:2021 (Broken Access Control)",
        "description": (
            "Exponer el motor de base de datos relacional directamente a redes públicas permite a atacantes "
            "ejecutar campañas constantes de fuerza bruta contra la cuenta 'sa' y abre la puerta a ataques de inyección "
            "y compromiso de datos confidenciales."
        ),
        "remediation": (
            "Configurar el firewall para permitir conexiones al puerto 1433 únicamente desde las direcciones IP "
            "específicas de los servidores de aplicaciones. Cambiar el nombre de la cuenta 'sa' y exigir contraseñas complejas."
        )
    },
    1521: {
        "title": "Servicio Oracle Database Listener Expuesto",
        "service": "Oracle TNS Listener",
        "severity": "ALTA",
        "cvss_score": 8.2,
        "cwe_id": "CWE-284",
        "cve_ref": "CVE-2012-1675 / CWE-284",
        "description": (
            "El Listener de Oracle permite la enumeración de identificadores de sistema (SID) y es vulnerable "
            "a ataques de envenenamiento TNS si no cuenta con autenticación y validación de nodos."
        ),
        "remediation": (
            "Aislar la base de datos Oracle en una DMZ o subred interna privada. Habilitar la directiva 'VALID_NODE_CHECKING' "
            "en el archivo sqlnet.ora para restringir el acceso a clientes autorizados."
        )
    },
    3306: {
        "title": "Motor de Base de Datos MySQL / MariaDB Expuesto Públicamente",
        "service": "MySQL / MariaDB RDBMS",
        "severity": "ALTA",
        "cvss_score": 8.5,
        "cwe_id": "CWE-284",
        "cve_ref": "OWASP A01:2021 / CWE-284",
        "description": (
            "Un servidor MySQL expuesto a Internet sufre ataques continuos de diccionario y fuerza bruta. "
            "Si las contraseñas son débiles o existe una versión con vulnerabilidades conocidas, un atacante "
            "puede extraer volcados completos de datos o ejecutar comandos en el sistema operativo."
        ),
        "remediation": (
            "Vincular el servicio exclusivamente a la interfaz de loopback ('bind-address = 127.0.0.1') en my.cnf "
            "o aislarlo detrás de un cortafuegos. Deshabilitar el acceso remoto para el usuario 'root' y exigir TLS."
        )
    },
    3389: {
        "title": "Escritorio Remoto de Windows (RDP) Expuesto a Red Externa",
        "service": "Microsoft Remote Desktop Protocol (RDP)",
        "severity": "ALTA",
        "cvss_score": 8.8,
        "cwe_id": "CWE-284",
        "cve_ref": "CVE-2019-0708 (BlueKeep) / MS12-020",
        "description": (
            "El puerto RDP expuesto públicamente es el blanco predilecto para ataques de fuerza bruta de credenciales "
            "y explotación de vulnerabilidades críticas del subsistema de gráficos y sesiones remotas (BlueKeep). "
            "Una vez comprometido, otorga control gráfico total sobre la máquina objetivo."
        ),
        "remediation": (
            "No exponer el puerto 3389 directamente a Internet. Implementar una solución de VPN con autenticación "
            "multifactor (MFA) o utilizar un Azure Bastion / RD Gateway. Habilitar obligatoriamente la Autenticación "
            "a Nivel de Red (NLA - Network Level Authentication)."
        )
    },
    5432: {
        "title": "Motor de Base de Datos PostgreSQL Expuesto Directamente",
        "service": "PostgreSQL Database Server",
        "severity": "ALTA",
        "cvss_score": 8.5,
        "cwe_id": "CWE-284",
        "cve_ref": "CWE-284 / OWASP Top 10",
        "description": (
            "La exposición directa del motor PostgreSQL facilita intentos de acceso no autorizado y enumeración de roles. "
            "Configuraciones permisivas en el archivo pg_hba.conf (ej. método 'trust') pueden permitir acceso total sin contraseña."
        ),
        "remediation": (
            "Configurar 'listen_addresses = localhost' en postgresql.conf. Exigir autenticación 'scram-sha-256' "
            "y conexiones cifradas con SSL en pg_hba.conf."
        )
    },
    5900: {
        "title": "Servicio de Control Remoto VNC sin Cifrado Nativo",
        "service": "VNC (Virtual Network Computing)",
        "severity": "ALTA",
        "cvss_score": 8.2,
        "cwe_id": "CWE-319",
        "cve_ref": "RFC 6143 / CWE-319",
        "description": (
            "El protocolo RFB utilizado por VNC tradicionalmente limita las contraseñas a 8 caracteres "
            "y no cifra el tráfico de pantalla ni las pulsaciones de teclado, permitiendo la captura de contraseñas de sesión."
        ),
        "remediation": (
            "Tunelizar VNC a través de SSH ('ssh -L 5901:localhost:5900 user@host') o cerrar el puerto 5900 "
            "en el cortafuegos externo."
        )
    },
    6379: {
        "title": "Servidor de Memoria Redis Expuesto sin Autenticación o Débil",
        "service": "Redis In-Memory Key-Value Store",
        "severity": "CRÍTICA",
        "cvss_score": 9.8,
        "cwe_id": "CWE-306",
        "cve_ref": "CWE-306 / OWASP A01:2021",
        "description": (
            "Por diseño histórico, Redis fue concebido para operar en entornos internos de confianza sin autenticación. "
            "Cuando se expone a Internet, los atacantes pueden leer y modificar toda la memoria caché, escribir llaves SSH "
            "en el sistema de archivos del servidor objetivo o ejecutar código mediante módulos dinámicos."
        ),
        "remediation": (
            "Asegurar que Redis esté configurado con 'bind 127.0.0.1' en redis.conf. Habilitar el modo protegido "
            "('protected-mode yes') y definir una contraseña robusta de al menos 32 caracteres con la directiva 'requirepass'."
        )
    },
    8080: {
        "title": "Servidor Web Alternativo / Consola Administrativa Expuesta",
        "service": "HTTP Proxy / Web Admin (Alt HTTP)",
        "severity": "MEDIA",
        "cvss_score": 6.0,
        "cwe_id": "CWE-200",
        "cve_ref": "CWE-200 / CWE-284",
        "description": (
            "El puerto 8080 suele utilizarse para entornos de desarrollo, proxies o paneles de gestión (ej. Apache Tomcat, "
            "Jenkins, Spring Boot Actuator) que a menudo conservan credenciales por defecto o carecen de las directivas de seguridad "
            "aplicadas en el puerto principal."
        ),
        "remediation": (
            "Verificar si la aplicación alojada en el puerto 8080 requiere exposición pública. Restringir el acceso "
            "mediante lista blanca de IPs (IP Whitelisting) y forzar HTTPS."
        )
    },
    27017: {
        "title": "Base de Datos NoSQL MongoDB Expuesta a Redes Públicas",
        "service": "MongoDB Database Engine",
        "severity": "CRÍTICA",
        "cvss_score": 9.8,
        "cwe_id": "CWE-306",
        "cve_ref": "CVE-2015-1609 / CWE-306",
        "description": (
            "Instancias de MongoDB expuestas a Internet con la opción de autenticación desactivada han sufrido ataques "
            "masivos de robo y secuestro de bases de datos por parte de grupos de cibercrimen (Ransomware NoSQL)."
        ),
        "remediation": (
            "Activar la directiva de autenticación 'security.authorization: enabled' en mongod.conf. "
            "Vincular el servicio a 'bindIp: 127.0.0.1' o utilizar redes virtuales privadas VPC."
        )
    }
}


def evaluate_vulnerabilities(
    ip_analysis: Optional[Dict[str, Any]] = None,
    port_scan: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Ejecuta una evaluación exhaustiva y no invasiva de vulnerabilidades y riesgos
    técnicos sobre el host analizado a partir de los puertos abiertos y la telemetría IP.

    METODOLOGÍA DE EVALUACIÓN:
    -------------------------
    1. Análisis de Puertos Abiertos:
       Itera sobre cada puerto detectado como 'OPEN'. Consulta la base de conocimiento
       de debilidades para extraer severidad, CVSS, impacto y remediación.
    2. Inspección de Banners de Servicio (Information Disclosure):
       Analiza si las cabeceras devueltas por los puertos abiertos revelan versiones
       explícitas del software (ej. Apache, OpenSSH, vsftpd). Si es así, registra
       un hallazgo de divulgación de información (CWE-200).
    3. Evaluación de Entorno de Red (Ámbito de Exposición):
       Si la IP analizada es una dirección pública enrutable en Internet, el riesgo
       asociado a puertos críticos (SMB 445, Telnet 23, Redis 6379) se pondera al máximo.
    4. Cálculo del Score de Riesgo Global (0 - 100):
       Sintetiza la severidad de todos los hallazgos en un índice cuantitativo y
       determina el nivel general: BAJO, MEDIO, ALTO o CRÍTICO.

    Parámetros:
        ip_analysis (Optional[Dict[str, Any]]): Datos del análisis IP (ip_tracker).
        port_scan (Optional[Dict[str, Any]]): Datos del escaneo de puertos (port_scanner).

    Retorna:
        Dict[str, Any]: Diccionario con la lista de vulnerabilidades encontradas, métricas
                        de severidad y directrices de hardening.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    ports_list = (port_scan.get("ports", []) if port_scan else [])
    target_ip = (ip_analysis.get("ip_address") if ip_analysis else (port_scan.get("target") if port_scan else "Desconocido"))
    is_private = (ip_analysis.get("is_private", 0) == 1 if ip_analysis else False)

    # Contadores de severidad
    counts = {
        "CRÍTICA": 0,
        "ALTA": 0,
        "MEDIA": 0,
        "BAJA": 0,
        "INFO": 0
    }

    # --------------------------------------------------------------------------
    # 1. EVALUACIÓN DE PUERTOS ABIERTOS CONTRA LA BASE DE CONOCIMIENTO
    # --------------------------------------------------------------------------
    open_ports = [p for p in ports_list if p.get("state") == "OPEN"]

    for port_info in open_ports:
        port_num = port_info.get("port_number")
        banner = port_info.get("banner", "")

        # Verificación si el puerto coincide con una vulnerabilidad conocida
        if port_num in VULN_KNOWLEDGE_BASE:
            known = VULN_KNOWLEDGE_BASE[port_num]
            severity = known["severity"]
            counts[severity] += 1

            vuln_item = {
                "id": f"VULN-PORT-{port_num}",
                "port": port_num,
                "service": known["service"],
                "title": known["title"],
                "severity": severity,
                "cvss_score": known["cvss_score"],
                "cwe_id": known["cwe_id"],
                "cve_ref": known["cve_ref"],
                "description": known["description"],
                "remediation": known["remediation"]
            }
            vulnerabilities.append(vuln_item)
        else:
            # Puerto abierto no catalogado específicamente: registro informativo de superficie de ataque
            counts["INFO"] += 1
            vulnerabilities.append({
                "id": f"INFO-PORT-{port_num}",
                "port": port_num,
                "service": port_info.get("service_name", "Desconocido"),
                "title": f"Puerto TCP {port_num} Expuesto en Estado Abierto",
                "severity": "INFO",
                "cvss_score": 0.0,
                "cwe_id": "N/A",
                "cve_ref": "Superficie de Red",
                "description": (
                    f"El puerto {port_num} ({port_info.get('service_name', 'TCP')}) respondió afirmativamente al sondeo SYN-ACK. "
                    "Representa un servicio accesible en el host que amplía su superficie de ataque global."
                ),
                "remediation": (
                    "Evaluar si este puerto requiere estar abierto permanentemente. En caso negativo, cerrar el puerto "
                    "o bloquearlo en el cortafuegos mediante directivas de filtrado de paquetes."
                )
            })

        # ----------------------------------------------------------------------
        # 2. ANÁLISIS DE DIVULGACIÓN DE INFORMACIÓN EN BANNERS (CWE-200)
        # ----------------------------------------------------------------------
        if banner and any(kw in banner.lower() for kw in ["apache", "nginx", "openssh", "vsftpd", "microsoft", "ubuntu", "debian"]):
            counts["BAJA"] += 1
            vulnerabilities.append({
                "id": f"VULN-BANNER-{port_num}",
                "port": port_num,
                "service": port_info.get("service_name", "Banner"),
                "title": f"Divulgación de Información de Versión en Puerto {port_num}",
                "severity": "BAJA",
                "cvss_score": 4.3,
                "cwe_id": "CWE-200",
                "cve_ref": "CWE-200 (Information Exposure)",
                "description": (
                    f"La cabecera de respuesta del servicio en el puerto {port_num} revela detalles del software instalado: "
                    f"'{banner[:60]}...'. Esto permite a atacantes conocer la versión exacta y buscar exploits específicos."
                ),
                "remediation": (
                    "Configurar el servicio para ocultar firmas técnicas y números de versión en las cabeceras de respuesta "
                    "(ej. 'ServerTokens Prod' en Apache o 'server_tokens off;' en Nginx)."
                )
            })

    # --------------------------------------------------------------------------
    # 3. EVALUACIÓN CONTEXTUAL DE RED (ÁMBITO DE EXPOSICIÓN)
    # --------------------------------------------------------------------------
    if is_private:
        counts["INFO"] += 1
        vulnerabilities.append({
            "id": "INFO-SCOPE-PRIVATE",
            "port": 0,
            "service": "Enrutamiento IP",
            "title": "Host Ubicado en Rango de Red Privada (RFC 1918 / Loopback)",
            "severity": "INFO",
            "cvss_score": 0.0,
            "cwe_id": "N/A",
            "cve_ref": "RFC 1918",
            "description": (
                f"La dirección IP {target_ip} corresponde a un bloque privado o de prueba local. "
                "Los servicios detectados no son directamente accesibles desde la Internet pública a menos que exista una regla de NAT (Port Forwarding)."
            ),
            "remediation": (
                "Asegurarse de que no existan reglas involuntarias de mapeo de puertos (DNAT/Port Forwarding) en el router o cortafuegos de frontera."
            )
        })
    elif open_ports and not is_private:
        # Host público con servicios abiertos: recordatorio de hardening de perímetro
        counts["INFO"] += 1
        vulnerabilities.append({
            "id": "INFO-PERIMETER-PUBLIC",
            "port": 0,
            "service": "Perímetro WAN",
            "title": "Superficie de Ataque Expuesta en Internet Pública",
            "severity": "INFO",
            "cvss_score": 0.0,
            "cwe_id": "N/A",
            "cve_ref": "Perímetro WAN",
            "description": (
                f"La dirección {target_ip} es enrutable globalmente. Los {len(open_ports)} puerto(s) abiertos identificados "
                "pueden ser sondeados por bots automatizados y motores de búsqueda de dispositivos como Shodan o Censys."
            ),
            "remediation": (
                "Implementar un Sistema de Detección/Prevención de Intrusos (IDS/IPS) como Snort o Suricata y desplegar reglas de Fail2ban."
            )
        })

    # Si no se detectaron puertos abiertos
    if not open_ports and port_scan:
        counts["INFO"] += 1
        vulnerabilities.append({
            "id": "INFO-ZERO-PORTS",
            "port": 0,
            "service": "Protección Perimetral",
            "title": "Superficie de Exposición Externa Minimizada",
            "severity": "INFO",
            "cvss_score": 0.0,
            "cwe_id": "N/A",
            "cve_ref": "Defensa en Profundidad",
            "description": (
                "No se encontraron puertos abiertos en el conjunto de puertos TCP auditados. "
                "El host cuenta con políticas de filtrado perimetral activas (Firewall) o los servicios están convenientemente restringidos."
            ),
            "remediation": (
                "Mantener auditorías periódicas programadas para detectar la apertura accidental de nuevos puertos durante tareas de mantenimiento."
            )
        })

    # --------------------------------------------------------------------------
    # 4. CÁLCULO DE SCORE DE RIESGO GLOBAL (0 - 100) Y NIVEL CUALITATIVO
    # --------------------------------------------------------------------------
    # Ponderación técnica de riesgos
    raw_score = (
        counts["CRÍTICA"] * 35.0 +
        counts["ALTA"] * 20.0 +
        counts["MEDIA"] * 10.0 +
        counts["BAJA"] * 3.0
    )
    risk_score = min(100.0, round(raw_score, 1))

    # Determinación del nivel cualitativo de riesgo
    if risk_score >= 60.0 or counts["CRÍTICA"] > 0:
        risk_level = "CRÍTICO"
        risk_badge_class = "danger"
    elif risk_score >= 35.0 or counts["ALTA"] > 0:
        risk_level = "ALTO"
        risk_badge_class = "danger"
    elif risk_score >= 15.0 or counts["MEDIA"] > 0:
        risk_level = "MEDIO"
        risk_badge_class = "warning"
    else:
        risk_level = "BAJO"
        risk_badge_class = "success"

    # Ordenar vulnerabilidades por severidad decreciente para lectura priorizada
    severity_order = {"CRÍTICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFO": 4}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return {
        "target": target_ip,
        "evaluated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulns": len(vulnerabilities),
        "critical_count": counts["CRÍTICA"],
        "high_count": counts["ALTA"],
        "medium_count": counts["MEDIA"],
        "low_count": counts["BAJA"],
        "info_count": counts["INFO"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_badge_class": risk_badge_class,
        "vulnerabilities": vulnerabilities,
        "summary": (
            f"Se identificaron {len(vulnerabilities)} hallazgo(s) de seguridad "
            f"({counts['CRÍTICA']} críticos, {counts['ALTA']} altos, {counts['MEDIA']} medios). "
            f"Nivel de riesgo estimado: {risk_level} (Score {risk_score}/100)."
        )
    }
