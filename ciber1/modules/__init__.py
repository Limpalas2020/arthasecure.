"""
===============================================================================
PAQUETE DE MÓDULOS DE CIBERSEGURIDAD, REDES Y PERSISTENCIA (CIBER-ANALYZER)
===============================================================================

Este archivo (__init__.py) define la carpeta 'modules' como un paquete oficial
de Python. Su propósito principal es estructurar la aplicación bajo el principio
de diseño de 'Separación de Responsabilidades' (Separation of Concerns - SoC),
garantizando una arquitectura modular y desacoplada del servidor web (Flask).

ARQUITECTURA DE SUBMÓDULOS DEL PAQUETE:
--------------------------------------
1. database.py:
   - Capa de persistencia y abstracción de datos relacionales en SQLite 3.
   - Manejo seguro de conexiones mediante Context Managers y consultas parametrizadas.
   - Implementa llaves foráneas (Foreign Keys) e integridad referencial en cascada.
   - Consolida métricas y telemetría histórica para nutrir el Dashboard.

2. ip_tracker.py:
   - Motor de análisis e inteligencia de direcciones de capa de red (OSINT).
   - Valida formatos canónicos IPv4 e IPv6 y resuelve nombres de dominio (FQDN).
   - Discrimina rangos privados (RFC 1918), bucle local (Loopback RFC 1122) y enlace local (APIPA).
   - Realiza consultas seguras a la API REST de geolocalización IP-API únicamente para rangos públicos.
   - Calcula la latencia de red mediante aperturas temporizadas de sockets TCP (Round-Trip Time).

3. port_scanner.py:
   - Motor de auditoría defensiva de capa de transporte (TCP).
   - Implementa concurrencia multihilo controlada con ThreadPoolExecutor (Worker Threads).
   - Evalúa estados de puertos (ABIERTO, CERRADO, FILTRADO) mediante el handshake SYN/SYN-ACK.
   - Reconocimiento de servicios mediante catálogo estandarizado IANA (HTTP, SSH, MySQL, etc.).
   - Captura pasiva y segura de firmas y cabeceras de servicio (Banner Grabbing no intrusivo).

4. pdf_generator.py:
   - Motor de compilación automatizada de informes de auditoría en formato PDF con ReportLab (Platypus).
   - Implementa un canvas personalizado de dos pasadas (NumberedCanvas) para cálculo dinámico de folios ('Página X de Y').
   - Formatea tablas corporativas con código de color de estados, recomendaciones de hardening y conclusiones técnicas.
"""

# Metadatos del paquete
__version__ = "1.0.0"
__author__ = "CIBER-ANALYZER Development Team"
__status__ = "Production / Academic Reference"
