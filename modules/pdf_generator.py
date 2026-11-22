"""
===============================================================================
MÓDULO DE GENERACIÓN AUTOMATIZADA DE INFORMES DE CIBERSEGURIDAD EN PDF
===============================================================================

Este módulo implementa el motor de compilación documental de la plataforma
CIBER-ANALYZER. Transforma los datos de auditoría de red (telemetría IP y escaneo
de puertos) en un informe ejecutivo formal en formato PDF de estándar industrial.

TECNOLOGÍA Y FUNDAMENTOS DE REPORTLAB PLATYPUS:
----------------------------------------------
ReportLab es la biblioteca líder en Python para generación programática de PDFs.
Este módulo utiliza su arquitectura de alto nivel denominada 'Platypus' (Page Layout
and Typography Using Scripts), la cual separa el contenido de su diagramación:

1. El Flujo de Documento (Story):
   El documento se concibe como una lista secuencial de objetos visuales denominados
   'Flowables' (párrafos, tablas, separadores, líneas horizontales). Platypus se
   encarga automáticamente del salto de línea, distribución de márgenes y paginación.

2. El Problema Clásico de Paginación ('Página X de Y'):
   En documentos de longitud variable generados al vuelo, cuando ReportLab está
   dibujando la Página 1, aún no sabe cuántas páginas ocuparán las tablas en total.
   Para solucionar esto, se implementa la clase 'NumberedCanvas', que intercepta el
   ciclo de renderizado en un esquema de DOS PASADAS (Two-Pass Canvas):
     - Pasada 1: Registra y acumula el contenido y calcula el número total de folios.
     - Pasada 2: Estampa dinámicamente el pie de página institucional ('Página 1 de 3')
       y el encabezado confidencial en cada página física.

3. Seguridad y Consistencia de Tipos:
   El módulo sanitiza cualquier entrada textual para evitar inyecciones de entidades
   XML en los Párrafos de ReportLab y normaliza valores numéricos de latencia.
"""

# ==============================================================================
# IMPORTACIÓN DE BIBLIOTECAS DEL SISTEMA Y REPORTLAB
# ==============================================================================
import os                      # Gestión de carpetas y comprobación de rutas en el sistema de archivos.
from datetime import datetime  # Marcas de tiempo formateadas para auditoría.
from typing import Dict, Any, List, Optional  # Anotaciones de tipos.

# Clases tipográficas y geométricas de ReportLab
from reportlab.lib import colors                   # Paleta de colores hexadecimales y RGB.
from reportlab.lib.pagesizes import letter        # Tamaño de hoja estándar Carta (8.5 x 11 pulgadas).
from reportlab.lib.units import inch              # Conversión a medidas en pulgadas (1 inch = 72 puntos).
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # Hojas de estilo tipográfico.

# Componentes de diagramación Platypus (Flowables)
from reportlab.platypus import (
    SimpleDocTemplate,  # Plantilla base de documento que gestiona los márgenes y páginas.
    Paragraph,          # Elemento de texto enriquecido con soporte de etiquetas XML seguras (<b>, <i>, <font>).
    Spacer,             # Espaciador vertical en blanco para separar secciones.
    Table,              # Estructura matricial de datos en filas y columnas.
    TableStyle,         # Reglas visuales para tablas (fondos, bordes, alineación, relleno).
    HRFlowable          # Línea divisoria horizontal decorativa.
)
from reportlab.pdfgen import canvas  # Capa de dibujo gráfico de bajo nivel.

# Módulo de evaluación de vulnerabilidades y riesgos defensivos
from modules import vuln_scanner

# ==============================================================================
# DIRECTORIO DE ALMACENAMIENTO DE INFORMES
# ==============================================================================
# Ruta absoluta hacia la carpeta 'public/reports' en la raíz del proyecto
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "public", "reports"))


class NumberedCanvas(canvas.Canvas):
    """
    Canvas personalizado de ReportLab que implementa un esquema de renderizado
    en DOS PASADAS para calcular con precisión matemática el total de páginas
    y estampar las marcas institucionales en cada folio.

    ¿CÓMO FUNCIONA EL CANVAS DE DOS PASADAS?
    ----------------------------------------
    1. En cada llamada a 'showPage()', en lugar de enviar la página inmediatamente
       a la impresora virtual del archivo PDF, se guarda una copia del estado
       gráfico en la lista '_saved_page_states'.
    2. Al finalizar todo el flujo en 'save()', se evalúa 'len(_saved_page_states)',
       que representa el total absoluto de páginas del informe.
    3. Se itera sobre cada página acumulada ejecutando 'draw_page_decorations()',
       estampando el encabezado corporativo y la leyenda: 'Página X de Y'.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Lista en memoria para acumular las páginas antes del volcado definitivo
        self._saved_page_states = []

    def showPage(self):
        """Interrumpe el cierre prematuro de página y almacena su estado en memoria."""
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """Calcula el folio total e imprime las decoraciones en cada página acumulada."""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        """
        Dibuja los elementos corporativos superiores (encabezado) e inferiores (pie de página).

        Parámetros:
            total_pages (int): Número total calculado de páginas que componen el documento.
        """
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#7C3AED"))  # Púrpura ARTHASECURE

        # ----------------------------------------------------------------------
        # ENCABEZADO SUPERIOR
        # ----------------------------------------------------------------------
        # Coordenadas: X=54pt (margen izquierdo de 0.75"), Y = Altura Hoja - 36pt
        self.drawString(54, letter[1] - 36, "ARTHASECURE // PLATAFORMA DE AUDITORÍA Y CIBERSEGURIDAD DEFENSIVA")
        self.drawRightString(letter[0] - 54, letter[1] - 36, "CONFIDENCIAL // INFORME TÉCNICO")

        # Línea divisoria superior fina (0.5 puntos)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # ----------------------------------------------------------------------
        # PIE DE PÁGINA INFERIOR
        # ----------------------------------------------------------------------
        self.line(54, 46, letter[0] - 54, 46)
        self.setFont("Helvetica", 8)
        self.drawString(54, 34, "Generado automáticamente por el motor de análisis de ciberseguridad.")
        page_str = f"Página {self._pageNumber} de {total_pages}"
        self.drawRightString(letter[0] - 54, 34, page_str)

        self.restoreState()


def generate_security_pdf(
    analysis_data: Dict[str, Any],
    scan_data: Optional[Dict[str, Any]] = None,
    output_filename: Optional[str] = None,
    vulnerabilities_data: Optional[Dict[str, Any]] = None
) -> str:
    """
    Construye, diseña y compila el informe técnico completo en formato PDF.

    SECCIONES DEL INFORME:
    ----------------------
    1. Cabecera Corporativa: Título del documento y línea divisoria azul eléctrico.
    2. Metadatos de Sesión: Fecha, objetivo evaluado, tipo de dirección y ámbito de red.
    3. Inteligencia y Geolocalización (OSINT): País, ciudad, ISP, ASN y RTT.
    4. Auditoría de Puertos TCP: Resumen y tabla detallada con firmas y estado.
    5. Evaluación de Vulnerabilidades y Riesgos (CVE/CWE): Matriz de hallazgos con severidad y mitigación.
    6. Observaciones Técnicas y Hardening.
    7. Conclusiones del Diagnóstico.

    Parámetros:
        analysis_data (Dict[str, Any]): Datos estructurados del rastreo IP.
        scan_data (Optional[Dict[str, Any]]): Resultados del escaneo de puertos (opcional).
        output_filename (Optional[str]): Nombre de archivo personalizado si se requiere.
        vulnerabilities_data (Optional[Dict[str, Any]]): Auditoría de vulnerabilidades defensivas.

    Retorna:
        str: Ruta absoluta en disco donde fue compilado y guardado físicamente el PDF.
    """
    # 0. Si no se proveyó la evaluación de vulnerabilidades, se calcula heurísticamente
    if not vulnerabilities_data:
        vulnerabilities_data = vuln_scanner.evaluate_vulnerabilities(analysis_data, scan_data)

    # 1. Asegurar la existencia física del directorio de salida
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # 2. Generar nombre de archivo único si no se proporcionó uno
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_ip = str(analysis_data.get("ip_address", "target")).replace(":", "_").replace(".", "_")

    if not output_filename:
        output_filename = f"Reporte_Seguridad_{target_ip}_{timestamp_str}.pdf"

    pdf_path = os.path.join(REPORTS_DIR, output_filename)

    # 3. Configuración del documento base con márgenes de 0.75 pulgadas (54 puntos)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    # 4. Definición de la jerarquía tipográfica personalizada
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#7C3AED"),
        spaceAfter=12
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6
    )
    body_text = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    body_italic = ParagraphStyle(
        "BodyItalic",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#64748B")
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1E293B")
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    # 'story' es la lista secuencial donde agregamos cada elemento del documento
    story = []

    # ==========================================================================
    # SECCIÓN 1: CABECERA Y TÍTULO
    # ==========================================================================
    story.append(Paragraph("INFORME DE ANÁLISIS DE RED Y CIBERSEGURIDAD", title_style))
    story.append(Paragraph("PLATAFORMA ARTHASECURE // AUDITORÍA TÉCNICA DEFENSIVA", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#7C3AED"), spaceAfter=14))

    # ==========================================================================
    # SECCIÓN 2: METADATOS DE LA EVALUACIÓN
    # ==========================================================================
    gen_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    meta_data = [
        [
            Paragraph("<b>Fecha y Hora:</b>", table_cell),
            Paragraph(gen_time, table_cell),
            Paragraph("<b>Objetivo Evaluado:</b>", table_cell),
            Paragraph(f"<code>{analysis_data.get('ip_address', 'N/A')}</code>", table_cell_bold)
        ],
        [
            Paragraph("<b>Tipo de Dirección:</b>", table_cell),
            Paragraph(str(analysis_data.get("ip_type", "IPv4")), table_cell),
            Paragraph("<b>Ámbito de Red:</b>", table_cell),
            Paragraph(str(analysis_data.get("scope_name", "Pública")), table_cell)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[1.3 * inch, 2.0 * inch, 1.4 * inch, 2.3 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # ==========================================================================
    # SECCIÓN 3: GEOLOCALIZACIÓN E INTELIGENCIA OSINT
    # ==========================================================================
    story.append(Paragraph("1. INFORMACIÓN GEOGRÁFICA Y DE ENRUTAMIENTO (OSINT)", section_heading))

    # Formateo seguro de latencia protegiendo contra tipos de datos mixtos
    raw_lat = analysis_data.get("latency_ms", -1.0)
    try:
        lat_float = float(raw_lat)
        latency_str = f"{lat_float} ms" if lat_float > 0 else "Sin respuesta directa (Filtrado/Local)"
    except (ValueError, TypeError):
        latency_str = str(raw_lat) if raw_lat else "N/A"

    geo_data = [
        [Paragraph("Parámetro", table_header), Paragraph("Valor Detectado", table_header)],
        [Paragraph("País", table_cell_bold), Paragraph(str(analysis_data.get("country", "Desconocido")), table_cell)],
        [Paragraph("Departamento / Región", table_cell_bold), Paragraph(str(analysis_data.get("region", "Desconocido")), table_cell)],
        [Paragraph("Ciudad", table_cell_bold), Paragraph(str(analysis_data.get("city", "Desconocido")), table_cell)],
        [Paragraph("Coordenadas Aprox. (Lat, Lon)", table_cell_bold), Paragraph(f"{analysis_data.get('latitude', 0.0)}, {analysis_data.get('longitude', 0.0)}", table_cell)],
        [Paragraph("Proveedor de Internet (ISP)", table_cell_bold), Paragraph(str(analysis_data.get("isp", "No disponible")), table_cell)],
        [Paragraph("Organización Titular", table_cell_bold), Paragraph(str(analysis_data.get("organization", "No disponible")), table_cell)],
        [Paragraph("Sistema Autónomo (ASN)", table_cell_bold), Paragraph(str(analysis_data.get("asn", "No disponible")), table_cell)],
        [Paragraph("Zona Horaria", table_cell_bold), Paragraph(str(analysis_data.get("timezone", "UTC")), table_cell)],
        [Paragraph("DNS Inverso (PTR)", table_cell_bold), Paragraph(str(analysis_data.get("reverse_dns", "Sin PTR")), table_cell)],
        [Paragraph("Latencia de Respuesta (RTT)", table_cell_bold), Paragraph(latency_str, table_cell)]
    ]
    geo_table = Table(geo_data, colWidths=[2.2 * inch, 4.8 * inch])
    geo_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),  # Encabezado azul marino oscuro
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(geo_table)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<i>Nota sobre geolocalización:</i> Las coordenadas físicas provistas son aproximaciones a nivel de "
        "enrutador/servidor del proveedor de servicios (ISP). No representan la ubicación domiciliaria exacta de ningún usuario.",
        body_italic
    ))
    story.append(Spacer(1, 14))

    # ==========================================================================
    # SECCIÓN 4: RESULTADOS DEL ESCANEO DE PUERTOS TCP
    # ==========================================================================
    story.append(Paragraph("2. AUDITORÍA DE PUERTOS TCP Y SERVICIOS", section_heading))

    if scan_data and scan_data.get("ports"):
        # Resumen consolidado en tarjeta superior
        stats_summary = [
            [
                Paragraph("<b>Total Evaluados:</b>", table_cell),
                Paragraph(str(scan_data.get("total_scanned", 0)), table_cell_bold),
                Paragraph("<b>Puertos Abiertos:</b>", table_cell),
                Paragraph(f"<font color='#059669'><b>{scan_data.get('open_ports', 0)}</b></font>", table_cell),
                Paragraph("<b>Puertos Cerrados:</b>", table_cell),
                Paragraph(f"<font color='#DC2626'><b>{scan_data.get('closed_ports', 0)}</b></font>", table_cell),
                Paragraph("<b>Tiempo:</b>", table_cell),
                Paragraph(f"{scan_data.get('duration_seconds', 0.0)} s", table_cell)
            ]
        ]
        stats_table = Table(
            stats_summary,
            colWidths=[1.1 * inch, 0.6 * inch, 1.2 * inch, 0.6 * inch, 1.2 * inch, 0.6 * inch, 0.9 * inch, 0.8 * inch]
        )
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF2F6")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 8))

        # Tabla detallada puerto por puerto
        port_rows = [
            [
                Paragraph("Puerto", table_header),
                Paragraph("Estado", table_header),
                Paragraph("Servicio Asociado (Catálogo IANA)", table_header),
                Paragraph("Latencia", table_header),
                Paragraph("Banner / Firma", table_header)
            ]
        ]

        for p in scan_data.get("ports", []):
            st = p.get("state", "CERRADO")
            # Códigos de color semánticos (Verde = Abierto, Rojo = Cerrado, Ámbar = Filtrado)
            state_color = "#059669" if st == "ABIERTO" else ("#DC2626" if st == "CERRADO" else "#D97706")
            state_html = f"<font color='{state_color}'><b>{st}</b></font>"

            banner_text = p.get("banner", "")
            if not banner_text:
                banner_text = "Sin banner detectado" if st == "ABIERTO" else "-"

            port_rows.append([
                Paragraph(f"<b>TCP {p.get('port_number')}</b>", table_cell),
                Paragraph(state_html, table_cell),
                Paragraph(p.get("service_name", "Desconocido"), table_cell),
                Paragraph(f"{p.get('response_time_ms', 0.0)} ms", table_cell),
                Paragraph(banner_text[:50], table_cell)
            ])

        ports_table = Table(port_rows, colWidths=[1.0 * inch, 1.0 * inch, 2.6 * inch, 0.9 * inch, 1.5 * inch])
        ports_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),  # Encabezado azul eléctrico
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(ports_table)
    else:
        story.append(Paragraph(
            "<i>No se ejecutó escaneo de puertos en esta sesión o no se detectaron puertos para la dirección evaluada.</i>",
            body_italic
        ))

    story.append(Spacer(1, 14))

    # ==========================================================================
    # SECCIÓN 3: EVALUACIÓN DEFENSIVA DE VULNERABILIDADES Y RIESGOS (CVE/CWE)
    # ==========================================================================
    story.append(Paragraph("3. EVALUACIÓN DEFENSIVA DE VULNERABILIDADES Y RIESGOS (CVE / CWE)", section_heading))

    risk_lvl = vulnerabilities_data.get("risk_level", "BAJO")
    risk_score = vulnerabilities_data.get("risk_score", 0.0)
    risk_color_hex = "#DC2626" if risk_lvl in ["CRÍTICO", "ALTO"] else ("#D97706" if risk_lvl == "MEDIO" else "#059669")

    # Resumen Ejecutivo de Métricas de Riesgo
    risk_summary_data = [
        [
            Paragraph("<b>Nivel de Riesgo Global:</b>", table_cell),
            Paragraph(f"<font color='{risk_color_hex}'><b>{risk_lvl}</b> (Score: {risk_score}/100)</font>", table_cell_bold),
            Paragraph("<b>Total Hallazgos:</b>", table_cell),
            Paragraph(f"<b>{vulnerabilities_data.get('total_vulns', 0)}</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>Críticas (CVSS >= 9.0):</b>", table_cell),
            Paragraph(f"<font color='#DC2626'><b>{vulnerabilities_data.get('critical_count', 0)}</b></font>", table_cell),
            Paragraph("<b>Altas (CVSS 7.0 - 8.9):</b>", table_cell),
            Paragraph(f"<font color='#EA580C'><b>{vulnerabilities_data.get('high_count', 0)}</b></font>", table_cell)
        ],
        [
            Paragraph("<b>Medias (CVSS 4.0 - 6.9):</b>", table_cell),
            Paragraph(f"<font color='#D97706'><b>{vulnerabilities_data.get('medium_count', 0)}</b></font>", table_cell),
            Paragraph("<b>Bajas / Info:</b>", table_cell),
            Paragraph(f"<font color='#2563EB'><b>{vulnerabilities_data.get('low_count', 0) + vulnerabilities_data.get('info_count', 0)}</b></font>", table_cell)
        ]
    ]
    risk_summary_table = Table(risk_summary_data, colWidths=[1.5 * inch, 2.0 * inch, 1.4 * inch, 2.1 * inch])
    risk_summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(risk_summary_table)
    story.append(Spacer(1, 8))

    # Matriz Desglosada de Vulnerabilidades y Remediaciones
    vulns_list = vulnerabilities_data.get("vulnerabilities", [])
    if vulns_list:
        vuln_rows = [
            [
                Paragraph("ID / CVE", table_header),
                Paragraph("Severidad", table_header),
                Paragraph("Servicio", table_header),
                Paragraph("Descripción y Riesgo", table_header),
                Paragraph("Remediación (Hardening)", table_header)
            ]
        ]
        for v in vulns_list:
            sev = v.get("severity", "INFO")
            sev_color = "#DC2626" if sev in ["CRÍTICA", "ALTA"] else ("#D97706" if sev == "MEDIA" else "#2563EB")
            vuln_rows.append([
                Paragraph(f"<b>{v.get('cve_ref', v.get('id', 'N/A'))}</b><br/><font color='#64748B'>{v.get('cwe_id', '')}</font>", table_cell),
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font><br/><small>CVSS {v.get('cvss_score', 0.0)}</small>", table_cell),
                Paragraph(f"<b>Puerto {v.get('port', 0)}</b><br/>{v.get('service', 'N/A')}", table_cell),
                Paragraph(f"<b>{v.get('title', '')}</b><br/>{v.get('description', '')}", table_cell),
                Paragraph(v.get("remediation", "Aplicar directrices de defensa en profundidad."), table_cell)
            ])

        vuln_table = Table(vuln_rows, colWidths=[1.1 * inch, 0.8 * inch, 1.1 * inch, 2.1 * inch, 1.9 * inch])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("<i>No se registraron vulnerabilidades ni puertos abiertos en el host evaluado.</i>", body_italic))

    story.append(Spacer(1, 14))

    # ==========================================================================
    # SECCIÓN 4: OBSERVACIONES TÉCNICAS Y RECOMENDACIONES
    # ==========================================================================
    story.append(Paragraph("4. OBSERVACIONES TÉCNICAS Y RECOMENDACIONES", section_heading))

    open_count = scan_data.get("open_ports", 0) if scan_data else 0
    if open_count > 0:
        obs_text = (
            f"Se identificaron <b>{open_count} puerto(s) en estado ABIERTO</b>. Los servicios expuestos a redes no confiables "
            "deben contar con mecanismos de autenticación robusta, certificados TLS vigentes y filtrado perimetral estricto. "
            "Se sugiere verificar si los puertos identificados requieren exposición pública obligatoria o si deben aislarse "
            "detrás de una Red Privada Virtual (VPN)."
        )
    else:
        obs_text = (
            "No se identificaron puertos abiertos en el conjunto de puertos analizado. La superficie de ataque externa del host "
            "se encuentra minimizada para los servicios muestreados o el tráfico se encuentra protegido por un cortafuegos (Firewall)."
        )
    story.append(Paragraph(obs_text, body_text))
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECCIÓN 5: CONCLUSIÓN DEL ANÁLISIS
    # ==========================================================================
    story.append(Paragraph("5. CONCLUSIÓN DEL ANÁLISIS", section_heading))
    conclusion_text = (
        f"El análisis automatizado sobre la dirección <b>{analysis_data.get('ip_address')}</b> culminó con éxito. "
        f"El nodo pertenece a la infraestructura de <b>{analysis_data.get('isp', 'la red evaluada')}</b> con presencia "
        f"en <b>{analysis_data.get('country', 'ubicación regional')}</b>. "
        "Este informe refleja el estado de conectividad y exposición de puertos en el instante exacto de su compilación."
    )
    story.append(Paragraph(conclusion_text, body_text))

    # 5. Compilación del documento utilizando el canvas de dos pasadas
    doc.build(story, canvasmaker=NumberedCanvas)

    return pdf_path
