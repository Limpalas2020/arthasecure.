/**
 * ==============================================================================
 * CIBER-ANALYZER // CLIENTE JAVASCRIPT UNIFICADO (ES6+)
 * ==============================================================================
 *
 * Este archivo centraliza la capa de interacción dinámica del cliente en el
 * navegador. Implementa una arquitectura asíncrona no bloqueante (Event-Driven)
 * utilizando el estándar moderno Fetch API de JavaScript para comunicarse con
 * el backend de Flask sin recargar la página (Single Page Experience en submódulos).
 *
 * MÓDULOS Y RESPONSABILIDADES:
 * ----------------------------
 * 1. initNavbarToggle(): Control del menú móvil responsivo (Hamburguesa).
 * 2. initContactForm(): Validación en cliente y envío AJAX del formulario de contacto.
 * 3. initToolsModule():
 *    - Manejo de presets de puertos TCP.
 *    - Orquestación de peticiones de escaneo (/api/track-ip, /api/scan-ports).
 *    - Animación del radar de escaneo y renderizado dinámico del DOM.
 *    - Gestión de la generación y descarga automática de reportes PDF.
 * 4. initDashboardCharts(): Inicialización y parametrización de gráficos con Chart.js.
 * 5. Funciones Utilitarias: Prevención de inyección XSS y visualización de alertas.
 * ==============================================================================
 */

// Evento principal: Se dispara cuando el documento HTML ha sido completamente analizado por el navegador
document.addEventListener("DOMContentLoaded", () => {
    initNavbarToggle();     // Inicializa el menú de navegación para móviles
    initContactForm();      // Inicializa el listener del formulario de contacto
    initToolsModule();      // Inicializa la consola de herramientas de auditoría
    initDashboardCharts();  // Inicializa los gráficos interactivos de Chart.js si existe telemetría
});

/* ==============================================================================
   1. NAVEGACIÓN Y MENÚ RESPONSIVO (MÓVILES)
   ==============================================================================
   ¿Qué sucede aquí?
   Cuando el usuario navega desde un teléfono o pantalla pequeña (ancho < 768px),
   la barra de enlaces se oculta. Al hacer clic en el botón '#navToggle', este
   controlador añade o remueve la clase CSS '.active' sobre '#navMenu', mostrando
   o replegando la lista de opciones y alternando el icono de barras por una 'X'.
*/
function initNavbarToggle() {
    const navToggle = document.getElementById("navToggle");
    const navMenu = document.getElementById("navMenu");

    if (navToggle && navMenu) {
        navToggle.addEventListener("click", () => {
            // Alterna la visibilidad del menú
            navMenu.classList.toggle("active");
            navMenu.classList.toggle("show");

            // Alterna el icono entre barras de menú y cruz de cierre
            const icon = navToggle.querySelector("i");
            if (icon) {
                icon.classList.toggle("fa-bars");
                icon.classList.toggle("fa-xmark");
            }
        });
    }
}

/* ==============================================================================
   2. FORMULARIO DE CONTACTO (SECCIÓN INICIO)
   ==============================================================================
   RECORRIDO TÉCNICO DE LA PETICIÓN:
   1. El usuario completa los campos y pulsa 'Enviar Mensaje'.
   2. 'e.preventDefault()' cancela el envío tradicional del formulario HTML,
      impidiendo que el navegador recargue la página en blanco.
   3. Se extraen y limpian los valores (.trim()) de cada campo.
   4. Se valida en el cliente que ningún campo esté vacío.
   5. Se desactiva el botón y se muestra un spinner animado para dar feedback inmediato.
   6. Se envía una petición HTTP POST asíncrona con 'fetch("/api/contact")' con cabecera
      'Content-Type: application/json'.
   7. Al recibir la respuesta del servidor Flask:
      - Si es HTTP 200 (éxito): Muestra un banner verde (.alert-success) y limpia el formulario.
      - Si es un error: Muestra un banner rojo (.alert-danger) con la causa reportada.
   8. El bloque 'finally' reactiva el botón en cualquier escenario.
*/
function initContactForm() {
    const contactForm = document.getElementById("contactForm");
    const contactAlert = document.getElementById("contactAlert");
    const submitBtn = document.getElementById("contactSubmitBtn");

    if (!contactForm) return;

    contactForm.addEventListener("submit", async (e) => {
        e.preventDefault(); // Detiene la recarga de página por defecto

        const fullName = document.getElementById("contactName").value.trim();
        const email = document.getElementById("contactEmail").value.trim();
        const subject = document.getElementById("contactSubject").value.trim();
        const message = document.getElementById("contactMessage").value.trim();

        // Validación preventiva en el lado del cliente
        if (!fullName || !email || !subject || !message) {
            showAlert(contactAlert, "Por favor completa todos los campos del formulario.", "danger");
            return;
        }

        // Estado de carga visual en el botón
        const originalBtnHtml = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Registrando mensaje...';

        try {
            // Envío asíncrono hacia el backend
            const response = await fetch("/api/contact", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ full_name: fullName, email, subject, message })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert(contactAlert, data.message || "Tu mensaje ha sido guardado exitosamente.", "success");
                contactForm.reset(); // Restablece los campos a su estado inicial
            } else {
                showAlert(contactAlert, data.error || "Ocurrió un error al procesar tu mensaje.", "danger");
            }
        } catch (error) {
            // Manejo de fallos en la capa de transporte (ej. servidor caído o sin red)
            showAlert(contactAlert, "Error de comunicación con el servidor: " + error.message, "danger");
        } finally {
            // Restaurar el botón original
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });
}

/* ==============================================================================
   3. MÓDULO DE AUDITORÍA Y HERRAMIENTAS (RASTREO IP & PUERTOS)
   ==============================================================================
   Mantiene variables en memoria durante la sesión del usuario para poder correlacionar
   la información geográfica con el escaneo de puertos y compilar el informe PDF.
*/
let currentAnalysisData = null;  // Almacena el resultado devuelto por /api/track-ip
let currentScanData = null;      // Almacena el resultado devuelto por /api/scan-ports
let currentVulnsData = null;     // Almacena la evaluación de vulnerabilidades y riesgos calculados
let currentAnalysisId = null;    // Clave primaria de la tabla analyses
let currentScanId = null;        // Clave primaria de la tabla port_scans

function initToolsModule() {
    const auditForm = document.getElementById("auditForm");
    if (!auditForm) return;

    const checkTrackIp = document.getElementById("checkTrackIp");
    const checkScanPorts = document.getElementById("checkScanPorts");
    const checkAuditVulns = document.getElementById("checkAuditVulns");
    const portsConfigSection = document.getElementById("portsConfigSection");
    const portsInput = document.getElementById("portsInput");
    const targetInput = document.getElementById("targetInput");
    const scannerLoader = document.getElementById("scannerLoader");
    const scannerMainText = document.getElementById("scannerMainText");
    const scannerSubText = document.getElementById("scannerSubText");
    const resultsArea = document.getElementById("resultsArea");
    const toolsAlertArea = document.getElementById("toolsAlertArea");
    const btnGeneratePdf = document.getElementById("btnGeneratePdf");

    // --------------------------------------------------------------------------
    // A. Alternar visibilidad de configuración de puertos
    // --------------------------------------------------------------------------
    if (checkScanPorts && portsConfigSection) {
        checkScanPorts.addEventListener("change", () => {
            // Si el usuario desmarca el escaneo de puertos, se ocultan los inputs de puertos
            portsConfigSection.style.display = checkScanPorts.checked ? "block" : "none";
        });
    }

    // --------------------------------------------------------------------------
    // B. Perfiles Rápidos de Puertos (.preset-btn)
    // --------------------------------------------------------------------------
    document.querySelectorAll(".preset-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            // Lee el atributo HTML5 'data-ports' del botón pulsado y lo copia al input
            const ports = btn.getAttribute("data-ports");
            if (portsInput && ports) {
                portsInput.value = ports;
                portsInput.focus();
            }
        });
    });

    // --------------------------------------------------------------------------
    // C. Envío y Orquestación del Análisis Operativo
    // --------------------------------------------------------------------------
    auditForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const target = targetInput.value.trim();
        const doTrack = checkTrackIp.checked;
        const doScan = checkScanPorts.checked;

        // Validaciones preventivas
        if (!target) {
            showAlert(toolsAlertArea, "Debe introducir una dirección IP o nombre de dominio.", "danger");
            targetInput.focus();
            return;
        }

        if (!doTrack && !doScan) {
            showAlert(toolsAlertArea, "Debe seleccionar al menos una operación (Rastreo IP o Escaneo de Puertos).", "danger");
            return;
        }

        // Limpieza de estados anteriores e inicio del radar de carga
        hideAlert(toolsAlertArea);
        resultsArea.style.display = "none";
        scannerLoader.style.display = "block";
        currentAnalysisData = null;
        currentScanData = null;
        currentVulnsData = null;
        currentAnalysisId = null;
        currentScanId = null;

        try {
            // ------------------------------------------------------------------
            // PASO 1: Rastreo de Capa de Red (IP OSINT)
            // ------------------------------------------------------------------
            if (doTrack) {
                scannerMainText.textContent = "Analizando dirección IP y resolviendo enrutamiento...";
                scannerSubText.textContent = "Consultando catálogo IANA, alcance de red y geolocalización aproximada.";

                const ipRes = await fetch("/api/track-ip", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target })
                });

                const ipData = await ipRes.json();
                if (!ipRes.ok || !ipData.success) {
                    if (ipData.limit_reached) {
                        updateTrialVisuals(0, 3, 3, true);
                        const limitErr = new Error(ipData.error || "Has alcanzado el límite de 3 análisis de la Prueba Gratuita.");
                        limitErr.limitReached = true;
                        throw limitErr;
                    }
                    throw new Error(ipData.error || "Fallo en la resolución o análisis de la dirección IP.");
                }

                // Si es usuario en prueba gratuita, actualizar indicadores visuales en tiempo real
                if (ipData.free_usage_left !== undefined && !ipData.is_authenticated) {
                    updateTrialVisuals(ipData.free_usage_left, ipData.free_usage_count, ipData.free_limit, ipData.free_usage_left <= 0);
                }

                currentAnalysisData = ipData;
                currentAnalysisId = ipData.analysis_id || null;
                if (ipData.vulnerabilities) {
                    currentVulnsData = ipData.vulnerabilities;
                }
                renderIpResults(ipData);
            } else {
                document.getElementById("cardIpResults").style.display = "none";
            }

            // ------------------------------------------------------------------
            // PASO 2: Escaneo de Capa de Transporte (Puertos TCP)
            // ------------------------------------------------------------------
            if (doScan) {
                scannerMainText.textContent = "Ejecutando sondeo concurrente de puertos TCP...";
                scannerSubText.textContent = "Verificando respuestas SYN-ACK e intentando captura no invasiva de firmas.";

                const portsValue = portsInput ? portsInput.value : "";
                const scanRes = await fetch("/api/scan-ports", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        target,
                        ports: portsValue,
                        analysis_id: currentAnalysisId // Vincula el escaneo con la IP analizada en la BD
                    })
                });

                const scanData = await scanRes.json();
                if (!scanRes.ok || !scanData.success) {
                    if (scanData.limit_reached) {
                        updateTrialVisuals(0, 3, 3, true);
                        const limitErr = new Error(scanData.error || "Has alcanzado el límite de 3 análisis de la Prueba Gratuita.");
                        limitErr.limitReached = true;
                        throw limitErr;
                    }
                    throw new Error(scanData.error || "Fallo durante la ejecución del escaneo de puertos.");
                }

                // Actualizar indicadores visuales de prueba gratuita
                if (scanData.free_usage_left !== undefined && !scanData.is_authenticated) {
                    updateTrialVisuals(scanData.free_usage_left, scanData.free_usage_count, scanData.free_limit, scanData.free_usage_left <= 0);
                }

                currentScanData = scanData;
                currentScanId = scanData.scan_id || null;
                if (scanData.vulnerabilities) {
                    currentVulnsData = scanData.vulnerabilities;
                }
                renderPortsResults(scanData);
            } else {
                document.getElementById("cardPortsResults").style.display = "none";
            }

            // ------------------------------------------------------------------
            // PASO 3: Renderizado de Vulnerabilidades y Gestión de Riesgos
            // ------------------------------------------------------------------
            const cardVulns = document.getElementById("cardVulnsResults");
            const doVulns = checkAuditVulns ? checkAuditVulns.checked : true;
            if (doVulns && currentVulnsData && cardVulns) {
                renderVulnsResults(currentVulnsData);
                cardVulns.style.display = "block";
            } else if (cardVulns) {
                cardVulns.style.display = "none";
            }

            // Marca temporal de finalización
            document.getElementById("resultTimestamp").textContent = "Auditoría finalizada el " + new Date().toLocaleString();
            resultsArea.style.display = "block";

            // Desplazamiento visual suave hacia la tarjeta de resultados
            resultsArea.scrollIntoView({ behavior: "smooth", block: "start" });

        } catch (err) {
            showAlert(toolsAlertArea, err.message, "danger", err.limitReached);
        } finally {
            // Se apaga el radar de escaneo
            scannerLoader.style.display = "none";
        }
    });

    // --------------------------------------------------------------------------
    // D. Generación y Descarga Automatizada del Informe PDF
    // --------------------------------------------------------------------------
    if (btnGeneratePdf) {
        btnGeneratePdf.addEventListener("click", async () => {
            if (!currentAnalysisData && !currentScanData) {
                showAlert(toolsAlertArea, "No hay datos de auditoría activos para generar un informe.", "danger");
                return;
            }

            const originalHtml = btnGeneratePdf.innerHTML;
            btnGeneratePdf.disabled = true;
            btnGeneratePdf.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Compilando PDF...';

            try {
                // Si el usuario solo escaneó puertos sin geolocalización, se formula una estructura base
                const payloadAnalysis = currentAnalysisData || {
                    ip_address: currentScanData.target,
                    ip_type: "IPv4",
                    scope_name: "Objetivo Evaluado",
                    country: "No consultado",
                    region: "No consultado",
                    city: "No consultado",
                    isp: "No consultado",
                    latency_ms: -1.0
                };

                const response = await fetch("/api/generate-pdf", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        analysis_data: payloadAnalysis,
                        scan_data: currentScanData,
                        vulnerabilities_data: currentVulnsData,
                        analysis_id: currentAnalysisId,
                        scan_id: currentScanId
                    })
                });

                const data = await response.json();
                if (response.ok && data.success && data.download_url) {
                    showAlert(toolsAlertArea, `Informe generado exitosamente: ${data.filename}. Iniciando descarga...`, "success");
                    // Dispara la descarga del archivo binario directamente en el navegador del usuario
                    window.location.href = data.download_url;
                } else {
                    throw new Error(data.error || "No se pudo generar el informe PDF.");
                }
            } catch (err) {
                showAlert(toolsAlertArea, "Error al generar informe PDF: " + err.message, "danger");
            } finally {
                btnGeneratePdf.disabled = false;
                btnGeneratePdf.innerHTML = originalHtml;
            }
        });
    }
}

/**
 * Renderiza dinámicamente la información de geolocalización e IP en el DOM.
 * @param {Object} data - Objeto de respuesta retornado por el endpoint /api/track-ip.
 */
function renderIpResults(data) {
    const card = document.getElementById("cardIpResults");
    if (!card) return;
    card.style.display = "block";

    document.getElementById("resIpAddress").textContent = data.ip_address || "-";
    document.getElementById("resIpType").textContent = data.ip_type || "IPv4";

    // Formateo de ubicación concatenando Ciudad, Región y País
    const loc = [data.city, data.region, data.country].filter(x => x && x !== "Desconocido" && x !== "No aplica").join(", ");
    document.getElementById("resLocation").textContent = loc || data.country || "Red Local / Privada";

    // Formateo seguro de latencia
    const latVal = typeof data.latency_ms === "number" && data.latency_ms > 0 
        ? `${data.latency_ms} ms` 
        : (data.latency_ms === -1.0 ? "Sin respuesta (Filtrado)" : (data.latency_ms || "Sin respuesta"));
    document.getElementById("resLatency").textContent = latVal;

    document.getElementById("resIsp").textContent = data.isp || "No disponible";
    document.getElementById("resOrg").textContent = data.organization || "No disponible";
    document.getElementById("resAsn").textContent = data.asn || "No disponible";

    const coords = (data.latitude || data.longitude) ? `${data.latitude}, ${data.longitude}` : "No disponibles (RFC 1918 / Local)";
    document.getElementById("resCoordinates").textContent = coords;

    document.getElementById("resTimezone").textContent = data.timezone || "UTC";
    document.getElementById("resReverseDns").textContent = data.reverse_dns || "Sin PTR inverso";

    // Actualiza la insignia (badge) visual de ámbito (Verde = Pública, Naranja = Privada)
    const badgeScope = document.getElementById("badgeIpScope");
    if (badgeScope) {
        badgeScope.textContent = data.scope_name || "Ámbito";
        badgeScope.className = data.is_private ? "badge badge-filtered" : "badge badge-open";
    }

    const techNotice = document.getElementById("resTechnicalNotice");
    if (techNotice && data.technical_notice) {
        techNotice.querySelector("span").textContent = data.technical_notice;
    }
}

/**
 * Renderiza la tabla y resumen de puertos TCP en el DOM.
 * @param {Object} data - Objeto de respuesta retornado por el endpoint /api/scan-ports.
 */
function renderPortsResults(data) {
    const card = document.getElementById("cardPortsResults");
    const tbody = document.getElementById("portsTableBody");
    if (!card || !tbody) return;
    card.style.display = "block";

    // Actualización de contadores de badges
    document.getElementById("badgeOpenCount").textContent = `${data.open_ports} Abiertos`;
    document.getElementById("badgeClosedCount").textContent = `${data.closed_ports} Cerrados`;
    document.getElementById("badgeFilteredCount").textContent = `${data.filtered_ports} Filtrados`;

    document.getElementById("scanMetaInfo").textContent = 
        `Objetivo: ${data.target} • Puertos Evaluados: ${data.total_scanned} • Duración: ${data.duration_seconds} segundos.`;

    // Limpia resultados anteriores
    tbody.innerHTML = "";

    const portsList = data.ports || [];
    if (portsList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No se obtuvieron resultados de sondeo.</td></tr>`;
        return;
    }

    // Inserción iterativa de cada fila de puerto
    portsList.forEach((p) => {
        const tr = document.createElement("tr");

        let badgeClass = "badge-closed";
        if (p.state === "ABIERTO") badgeClass = "badge-open";
        else if (p.state === "FILTRADO") badgeClass = "badge-filtered";

        // Protección contra inyecciones XSS al renderizar el banner del servicio
        const bannerText = p.banner 
            ? escapeHtml(p.banner) 
            : (p.state === "ABIERTO" ? '<span style="color: var(--text-muted); font-size: 0.8rem;">Sin banner</span>' : "-");

        tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-weight: 600; color: #60a5fa;">TCP ${p.port_number}</td>
            <td><span class="badge ${badgeClass}">${p.state}</span></td>
            <td>${escapeHtml(p.service_name || "Desconocido")}</td>
            <td style="font-family: var(--font-mono);">${p.response_time_ms} ms</td>
            <td style="font-family: var(--font-mono); font-size: 0.8rem; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${bannerText}</td>
        `;

        tbody.appendChild(tr);
    });
}

/**
 * Renderiza la tarjeta de hallazgos de vulnerabilidades y métricas de riesgo en el DOM.
 * @param {Object} vulnData - Objeto retornado por el motor vuln_scanner en el backend.
 */
function renderVulnsResults(vulnData) {
    const cardVulns = document.getElementById("cardVulnsResults");
    if (!cardVulns || !vulnData) return;

    // Métricas numéricas superiores
    const riskScoreEl = document.getElementById("resRiskScore");
    const critEl = document.getElementById("resCriticalCount");
    const highEl = document.getElementById("resHighCount");
    const medEl = document.getElementById("resMediumCount");
    const lowEl = document.getElementById("resLowCount");

    if (riskScoreEl) riskScoreEl.textContent = `${vulnData.risk_score || 0} / 100`;
    if (critEl) critEl.textContent = vulnData.critical_count || 0;
    if (highEl) highEl.textContent = vulnData.high_count || 0;
    if (medEl) medEl.textContent = vulnData.medium_count || 0;
    if (lowEl) lowEl.textContent = (vulnData.low_count || 0) + (vulnData.info_count || 0);

    const badgeRiskLevel = document.getElementById("badgeRiskLevel");
    if (badgeRiskLevel) {
        badgeRiskLevel.textContent = `Riesgo: ${vulnData.risk_level || 'BAJO'}`;
        badgeRiskLevel.className = `badge badge-${vulnData.risk_badge_class || 'info'}`;
    }

    const summaryText = document.getElementById("vulnSummaryText");
    if (summaryText) {
        summaryText.textContent = vulnData.summary || "Auditoría de vulnerabilidades completada.";
    }

    // Tabla de hallazgos
    const tbody = document.getElementById("vulnsTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const list = vulnData.vulnerabilities || [];
    if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No se identificaron vulnerabilidades en el objetivo.</td></tr>`;
        return;
    }

    list.forEach((v) => {
        const tr = document.createElement("tr");

        let sevBadgeClass = "badge-info";
        if (v.severity === "CRÍTICA") sevBadgeClass = "badge-danger";
        else if (v.severity === "ALTA") sevBadgeClass = "badge-danger";
        else if (v.severity === "MEDIA") sevBadgeClass = "badge-warning";
        else if (v.severity === "BAJA") sevBadgeClass = "badge-primary";

        tr.innerHTML = `
            <td>
                <span style="font-family: var(--font-mono); font-weight: 700; color: #38bdf8;">${escapeHtml(v.cve_ref || v.id)}</span>
                <br/><small style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(v.cwe_id || '')}</small>
            </td>
            <td>
                <span class="badge ${sevBadgeClass}">${escapeHtml(v.severity)}</span>
                <br/><small style="color: var(--text-muted); font-family: var(--font-mono); font-size: 0.75rem;">CVSS ${v.cvss_score || 0}</small>
            </td>
            <td>
                <strong style="color: var(--text-primary); font-size: 0.88rem;">${v.port ? 'Puerto ' + v.port : 'Host'}</strong>
                <br/><small style="color: var(--text-secondary);">${escapeHtml(v.service || 'N/A')}</small>
            </td>
            <td>
                <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">${escapeHtml(v.title || '')}</div>
                <div style="font-size: 0.83rem; color: var(--text-secondary); line-height: 1.4;">${escapeHtml(v.description || '')}</div>
            </td>
            <td>
                <div style="font-size: 0.83rem; color: #34d399; line-height: 1.4; background: rgba(16, 185, 129, 0.08); padding: 0.5rem; border-radius: var(--radius-sm); border-left: 3px solid #10b981;">
                    <i class="fa-solid fa-wrench" style="margin-right: 0.3rem;"></i>
                    ${escapeHtml(v.remediation || 'Aplicar directrices de hardening y defensa en profundidad.')}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/* ==============================================================================
   4. DASHBOARD & RENDERIZADO DE GRÁFICOS (CHART.JS)
   ==============================================================================
   Esta función toma el payload JSON seguro inyectado en la plantilla dashboard.html
   (<script id="dashboardData">) y construye las 4 instancias de gráficos de Chart.js
   personalizando paletas de colores neón y configurando escalas oscuras.
*/
function initDashboardCharts() {
    const dataElement = document.getElementById("dashboardData");
    if (!dataElement || typeof Chart === "undefined") return;

    let chartData = {};
    try {
        chartData = JSON.parse(dataElement.textContent || "{}");
    } catch (e) {
        console.error("Error al parsear datos analíticos de Chart.js:", e);
        return;
    }

    // Configuración global de fuentes y colores para el modo oscuro
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";

    // --------------------------------------------------------------------------
    // GRÁFICO 1: Distribución por Tipo de Protocolo IP (IPv4 vs IPv6) - Doughnut
    // --------------------------------------------------------------------------
    const ctxIp = document.getElementById("chartIpTypes");
    if (ctxIp) {
        const ipTypes = chartData.ip_types || {};
        const labels = Object.keys(ipTypes).length ? Object.keys(ipTypes) : ["IPv4", "IPv6"];
        const values = Object.keys(ipTypes).length ? Object.values(ipTypes) : [0, 0];

        new Chart(ctxIp, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: ["#3b82f6", "#06b6d4", "#a78bfa"],
                    borderColor: "#151e32",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom" }
                }
            }
        });
    }

    // --------------------------------------------------------------------------
    // GRÁFICO 2: Distribución de Estados de Puertos (Bar Chart)
    // --------------------------------------------------------------------------
    const ctxPorts = document.getElementById("chartPorts");
    if (ctxPorts) {
        const pDist = chartData.ports_distribution || { abiertos: 0, cerrados: 0, filtrados: 0 };
        new Chart(ctxPorts, {
            type: "bar",
            data: {
                labels: ["Abiertos", "Cerrados", "Filtrados"],
                datasets: [{
                    label: "Cantidad",
                    data: [pDist.abiertos || 0, pDist.cerrados || 0, pDist.filtrados || 0],
                    backgroundColor: ["#10b981", "#ef4444", "#f59e0b"],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // --------------------------------------------------------------------------
    // GRÁFICO 3: Top Servicios Abiertos más Recurrentes (Horizontal Bar)
    // --------------------------------------------------------------------------
    const ctxServices = document.getElementById("chartServices");
    if (ctxServices) {
        const topServices = chartData.top_services || [];
        const labels = topServices.length ? topServices.map(s => s.service.split("(")[0].trim()) : ["Sin datos"];
        const counts = topServices.length ? topServices.map(s => s.count) : [0];

        new Chart(ctxServices, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Ocurrencias",
                    data: counts,
                    backgroundColor: "#60a5fa",
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: "y", // Gráfico en orientación horizontal para legibilidad de nombres
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    },
                    y: {
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // --------------------------------------------------------------------------
    // GRÁFICO 4: Distribución Geográfica por País de Origen (Bar Chart)
    // --------------------------------------------------------------------------
    const ctxCountries = document.getElementById("chartCountries");
    if (ctxCountries) {
        const topCountries = chartData.top_countries || [];
        const labels = topCountries.length ? topCountries.map(c => c.country) : ["Sin datos"];
        const counts = topCountries.length ? topCountries.map(c => c.count) : [0];

        new Chart(ctxCountries, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "IPs Georreferenciadas",
                    data: counts,
                    backgroundColor: "#38bdf8",
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

/* ==============================================================================
   5. UTILIDADES Y FUNCIONES AUXILIARES
   ============================================================================== */

/**
 * Actualiza en tiempo real los elementos visuales de la versión de prueba gratuita:
 * texto de contador en la consola, badge del menú de navegación y estado de las píldoras.
 *
 * @param {number} freeLeft - Usos restantes en la prueba.
 * @param {number} freeCount - Usos ya consumidos.
 * @param {number} freeLimit - Límite global (ej. 3).
 * @param {boolean} isLimitReached - Si el usuario ya no tiene usos disponibles.
 */
function updateTrialVisuals(freeLeft, freeCount, freeLimit = 3, isLimitReached = false) {
    const trialTextCount = document.getElementById("trialTextCount");
    const navTrialCount = document.getElementById("navTrialCount");
    const navTrialBadge = document.getElementById("navTrialBadge");
    const trialBadgeState = document.getElementById("trialBadgeState");
    const trialStatusBanner = document.getElementById("trialStatusBanner");
    const trialStatusDesc = document.getElementById("trialStatusDesc");

    // Actualiza textos numéricos
    if (trialTextCount) trialTextCount.textContent = freeLeft;
    if (navTrialCount) navTrialCount.textContent = freeLeft;

    // Si agotó los usos, aplica estilos de alerta y bloqueo
    if (isLimitReached || freeLeft <= 0) {
        if (navTrialBadge) navTrialBadge.classList.add("depleted");
        if (trialStatusBanner) trialStatusBanner.classList.add("depleted");
        if (trialBadgeState) {
            trialBadgeState.className = "badge badge-danger";
            trialBadgeState.textContent = "Límite Alcanzado";
        }
        if (trialStatusDesc) {
            trialStatusDesc.textContent = "Ha alcanzado el límite de 3 análisis de la versión de prueba. Inicie sesión con la cuenta de pago para continuar sin restricciones.";
        }
    }

    // Actualiza visualmente cada píldora de slot
    for (let i = 1; i <= freeLimit; i++) {
        const pill = document.getElementById(`usagePill${i}`);
        if (pill) {
            if (i <= freeCount) {
                pill.className = "usage-pill used";
                pill.innerHTML = `<i class="fa-solid fa-check"></i> <span>Análisis ${i} (Usado)</span>`;
            } else {
                pill.className = "usage-pill available";
                pill.innerHTML = `<i class="fa-solid fa-bolt"></i> <span>Análisis ${i} (Disponible)</span>`;
            }
        }
    }
}

/**
 * Muestra un contenedor de alerta formateado con iconos temáticos y botón opcional de login.
 * @param {HTMLElement} container - Elemento HTML que contendrá la alerta.
 * @param {string} message - Mensaje informativo o de error a presentar.
 * @param {string} type - Tipo de alerta ('success', 'danger', 'info', 'warning').
 * @param {boolean} showLoginBtn - Si es True, añade un botón directo a /login.
 */
function showAlert(container, message, type = "info", showLoginBtn = false) {
    if (!container) return;
    const iconClass = type === "success" 
        ? "fa-circle-check" 
        : (type === "danger" ? "fa-circle-exclamation" : "fa-circle-info");

    let loginButtonHtml = "";
    if (showLoginBtn) {
        loginButtonHtml = `
            <div style="margin-top: 0.85rem;">
                <a href="/login" class="btn btn-primary" style="padding: 0.45rem 1rem; font-size: 0.88rem; text-decoration: none; display: inline-flex; align-items: center; gap: 0.5rem;">
                    <i class="fa-solid fa-user-lock"></i> Iniciar Sesión con Cuenta de Pago (admin / admin)
                </a>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="alert alert-${type}">
            <div style="display: flex; gap: 0.75rem; align-items: flex-start;">
                <i class="fa-solid ${iconClass}" style="margin-top: 0.2rem;"></i>
                <div style="flex: 1;">
                    <div>${escapeHtml(message)}</div>
                    ${loginButtonHtml}
                </div>
            </div>
        </div>
    `;
    container.style.display = "block";
}

/**
 * Oculta y limpia el contenedor de alertas.
 * @param {HTMLElement} container - Elemento HTML a ocultar.
 */
function hideAlert(container) {
    if (!container) return;
    container.style.display = "none";
    container.innerHTML = "";
}

/**
 * Sanitiza cadenas de texto para prevenir ataques de Cross-Site Scripting (XSS).
 * Reemplaza caracteres sensibles (&, <, >, ", ') por sus entidades HTML seguras.
 * @param {string} text - Cadena sin sanitizar.
 * @returns {string} Cadena sanitizada.
 */
function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
