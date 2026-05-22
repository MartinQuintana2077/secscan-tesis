import { useState, useEffect, useCallback } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useNavigate,
  useParams,
  useLocation
} from "react-router-dom";
import { triggerN8nScan, deepScan, getDevices, getVulnerabilities, checkHealth, installNmap, getScanDevices, getScanDetails, getScanHistory } from "./services/api";
import "./index.css";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import NetworkTree, { getDeviceIcon } from "./components/NetworkTree";

/* ========== PROTECTED ROUTE ========== */
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading-screen">Cargando sesión...</div>;
  if (!user) return <LoginPage />;
  return children;
};

/* ========== NAVBAR ========== */
function Navbar() {
  const { user, logout } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <>
      <nav className="navbar">
        <div className="navbar-left" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {user && (
            <button 
              className="navbar-hamburger" 
              onClick={() => setSidebarOpen(true)}
              aria-label="Abrir menú"
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                gap: '5px',
                padding: '8px',
                zIndex: 110,
                transition: 'all 0.3s ease'
              }}
            >
              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>
              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>
              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>
            </button>
          )}
          
          <a href="/" className="navbar-logo">
            <div className="navbar-logo-icon">SS</div>
            <div className="navbar-logo-text">
              Sec<span>Scan</span>
            </div>
          </a>
        </div>
        
        <div className="navbar-right">
          <div className="navbar-status">
            <div className="navbar-status-dot" />
            Motor Activo
          </div>
        </div>
      </nav>

      {/* ========== SIDEBAR PANEL ========== */}
      {user && (
        <>
          <div 
            className={`sidebar-overlay ${sidebarOpen ? 'active' : ''}`} 
            onClick={() => setSidebarOpen(false)}
          />
          
          <div className={`sidebar-panel ${sidebarOpen ? 'active' : ''}`}>
            <div className="sidebar-header">
              <div className="sidebar-logo">
                <div className="sidebar-logo-icon">SS</div>
                <div className="sidebar-logo-text">Sec<span>Scan</span></div>
              </div>
              <button 
                className="sidebar-close-btn" 
                onClick={() => setSidebarOpen(false)}
                aria-label="Cerrar menú"
              >
                &times;
              </button>
            </div>

            <div className="sidebar-profile-card">
              <div className="sidebar-avatar-wrapper">
                <img 
                  src={user.photoURL || "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y"} 
                  alt={user.displayName} 
                  className="sidebar-avatar" 
                  referrerPolicy="no-referrer"
                />
                <span className="sidebar-status-badge"></span>
              </div>
              
              <div className="sidebar-user-details">
                <h3 className="sidebar-user-name">{user.displayName}</h3>
                <span className="sidebar-user-email">{user.email || "Usuario Invitado"}</span>
                <span className="sidebar-user-role">🛡️ Auditor de Redes</span>
              </div>
            </div>

            <div className="sidebar-menu">
              <div className="sidebar-menu-section-title">Navegación</div>
              <a href="/" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>
                🏠 Inicio Dashboard
              </a>
              <a href="/history" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>
                📊 Historial de Auditorías
              </a>
            </div>

            <div className="sidebar-footer">
              <button 
                className="sidebar-logout-btn" 
                onClick={() => {
                  setSidebarOpen(false);
                  logout();
                }}
              >
                🚪 Cerrar Sesión
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}

/* ========== HOME ========== */
/* ========== HOME (BENTO GRID DESIGN) ========== */
function Home() {
  const navigate = useNavigate();
  const [scanning, setScanning] = useState(false);
  const [bgTaskActive, setBgTaskActive] = useState(false);
  const [scanMsg, setScanMsg] = useState("");
  const [showRangeModal, setShowRangeModal] = useState(false);
  const [rangeIp, setRangeIp] = useState("");
  const [devicesFound, setDevicesFound] = useState(0);
  const [nmapMissing, setNmapMissing] = useState(false);
  const [installingNmap, setInstallingNmap] = useState(false);
  const [isPassive, setIsPassive] = useState(false);

  // Estados nuevos para Bento Grid
  const [historyList, setHistoryList] = useState([]);
  const [consoleLogs, setConsoleLogs] = useState([
    "⚙️ SecScan CLI v1.2.0 - Motor de Auditoría y Redes Activo.",
    "👉 Elige un método de escaneo en los paneles interactivos del Bento Grid para inicializar...",
    "🛡️ Listo para monitoreo continuo en subredes locales."
  ]);

  const { getToken } = useAuth();

  // Cargar historial para el Network Switcher
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const token = await getToken();
        const data = await getScanHistory(token);
        if (data.status === "ok" && data.scans) {
          // Filtrar y ordenar por fecha para mostrar los más recientes
          const sorted = [...data.scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
          setHistoryList(sorted.slice(0, 5)); // Mostrar los últimos 5
        }
      } catch (e) {
        console.error("Error al cargar historial", e);
      }
    };
    fetchHistory();
  }, [getToken]);

  const animateLogs = (logsArray, onFinish) => {
    setConsoleLogs([]);
    let index = 0;
    const interval = setInterval(() => {
      if (index < logsArray.length) {
        setConsoleLogs(prev => [...prev, logsArray[index]]);
        index++;
        setTimeout(() => {
          const el = document.getElementById("console-logs-container");
          if (el) el.scrollTop = el.scrollHeight;
        }, 50);
      } else {
        clearInterval(interval);
        if (onFinish) onFinish();
      }
    }, 350); // Velocidad óptima de simulación
    return interval;
  };

  const handleFullScan = async (passiveScan = false) => {
    if (bgTaskActive) {
      alert("Ya hay un escaneo en progreso. Por favor, espera a que termine.");
      return;
    }

    try {
      const token = await getToken();
      const health = await checkHealth(token);
      if (!health.nmap_installed) {
        setNmapMissing(true);
        return;
      }
    } catch (e) {}

    setScanning(true);
    setBgTaskActive(true);
    setDevicesFound(0);
    setScanMsg(passiveScan ? "Inicializando escaneo pasivo indetectable..." : "Conectando con el motor de escaneo activo...");

    // Iniciar consola vacía
    setConsoleLogs(["🚀 SecScan Daemon - Conectando con el motor backend..."]);

    try {
      const token = await getToken();
      const scanId = crypto.randomUUID();

      // Disparamos el escaneo pasando el parámetro passive correspondientemente
      // El backend ahora responderá de inmediato e iniciará en 2do plano
      const scanResult = await triggerN8nScan("auto", token, scanId, passiveScan);
      
      if (passiveScan) {
        setScanMsg("🤫 Modo Pasivo (ARP Caché) — Leyendo memoria local...");
      } else if (scanResult.modo === "n8n") {
        setScanMsg("⚡ Modo Turbo (n8n) — Escaneando tu red en paralelo...");
      } else {
        setScanMsg("Escaneando tu red. Esperando resultados...");
      }

      // Función para auto-scroll de la terminal
      const scrollToBottom = () => {
        setTimeout(() => {
          const el = document.getElementById("console-logs-container");
          if (el) el.scrollTop = el.scrollHeight;
        }, 50);
      };

      // Polling de resultados (ahora empieza más rápido para captar los primeros logs)
      setTimeout(async () => {
        const maxPolls = 150;
        let polls = 0;
        const checkResults = setInterval(async () => {
          polls++;
          try {
            const token = await getToken();
            const res = await getScanDetails(scanId, token);
            if (res.status === "ok" && res.details) {
              const { devices_found = 0, total_targets = 1, status, logs = [] } = res.details;
              
              // Actualizar logs reales en vivo!
              if (logs.length > 0) {
                setConsoleLogs(logs);
                scrollToBottom();
              }
              
              setDevicesFound(devices_found);
              
              if (!passiveScan && status !== "completed") {
                setScanMsg(`Auditando puertos... (${devices_found} / ${total_targets || '?'}) dispositivos listos`);
              }

              // Condición de éxito: el backend marca status como 'completed'
              if (status === "completed" || (devices_found >= total_targets && total_targets > 0 && polls >= 3)) {
                clearInterval(checkResults);
                setScanning(false);
                setBgTaskActive(false);
                setTimeout(() => {
                  navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });
                }, 1000); // Pequeño delay para ver el último log de éxito
              }
            }

            if (polls >= maxPolls) {
              clearInterval(checkResults);
              setScanning(false);
              setBgTaskActive(false);
              navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });
            }
          } catch (e) {
             console.error("Error polling", e);
          }
        }, 1500); // Polling más rápido (1.5s) para sensación de tiempo real
      }, 1000);
    } catch (err) {
      setScanning(false);
      setBgTaskActive(false);
      alert("Error de conexión. ¿El backend está encendido?");
    }
  };

  const handleRangeScan = async () => {
    if (!rangeIp.trim()) return;
    if (bgTaskActive) {
      alert("Ya hay un escaneo en progreso. Por favor, espera a que termine.");
      return;
    }

    try {
      const token = await getToken();
      const health = await checkHealth(token);
      if (!health.nmap_installed) {
        setShowRangeModal(false);
        setNmapMissing(true);
        return;
      }
    } catch (e) {}

    setShowRangeModal(false);
    setScanning(true);
    setBgTaskActive(true);
    setScanMsg(`Escaneando objetivo: ${rangeIp}...`);
    
    setConsoleLogs([
      `⚙️ SecScan CLI - Iniciando escaneo específico para: ${rangeIp}`,
      `[i] Sondeando puertos en paralelo con timeouts estrictos...`
    ]);

    try {
      const token = await getToken();
      const data = await deepScan(rangeIp.trim(), token);
      setScanning(false);
      setBgTaskActive(false);
      navigate("/results", {
        state: {
          data: {
            status: "ok",
            total_dispositivos: 1,
            resultados: [data],
          },
          tipo: `IP Específica: ${rangeIp}`,
        },
      });
    } catch (err) {
      setScanning(false);
      setBgTaskActive(false);
      alert("Error de conexión con el backend. ¿Está Uvicorn encendido?");
    }
  };

  const handleInstallNmap = async () => {
    setInstallingNmap(true);
    try {
      const token = await getToken();
      const resp = await installNmap(token);
      if (resp.status === "ok") {
        setNmapMissing(false);
        alert("¡Motor Nmap inyectado y habilitado correctamente!");
      } else {
        alert("Error de instalación: " + resp.mensaje);
      }
    } catch (e) {
      alert("Error crítico ejecutando el instalador.");
    }
    setInstallingNmap(false);
  };

  return (
    <div className="page-container fade-in">
      <div className="home-hero">
        <h1 className="home-title">
          Monitoreo de <span>Vulnerabilidades</span>
        </h1>
        <p className="home-subtitle">
          Plataforma de ciberseguridad industrial y comercial. Auditoría activa y pasiva integrada para PYMEs e IoT.
        </p>
      </div>

      {/* ==================== BENTO GRID LAYOUT ==================== */}
      <div className="bento-grid">
        
        {/* PANEL 1: PANEL DE CONTROL DE ESCANEO (LARGE CARD) */}
        <div className="bento-card bento-large-scan slide-up">
          <div className="bento-badge main">🛰️ AUDITORÍA DE RED</div>
          <h2 className="bento-card-title">Lanzar Auditoría Inteligente</h2>
          <p className="bento-card-desc">
            Escanea tu subred local completa, descubre la topología y extensores intermedios en cascada y detecta puertos vulnerables expuestos.
          </p>

          <div className="scanner-controls-box">
            <button 
              className="bento-btn bento-btn-primary" 
              onClick={() => handleFullScan(false)}
              disabled={bgTaskActive}
            >
              🚀 Iniciar Escaneo Activo
            </button>
            
            <button 
              className="bento-btn bento-btn-secondary" 
              onClick={() => handleFullScan(true)}
              disabled={bgTaskActive}
            >
              🤫 Iniciar Escaneo Pasivo
            </button>
          </div>

          {scanning && (
            <div className="bento-status-overlay">
              <div className="bento-status-spinner-row">
                <div className="bento-spinner-sm" />
                <div>
                  <div className="bento-status-text">
                    {scanMsg}
                  </div>
                  {devicesFound > 0 && (
                    <div style={{ fontSize: "12px", color: "var(--accent-green)", marginTop: "4px" }}>
                      🟢 {devicesFound} dispositivos detectados
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* PANEL 2: CONSOLA DE COMANDOS EN VIVO (LARGE TERMINAL CARD) */}
        <div className="bento-card bento-terminal slide-up" style={{ animationDelay: "0.05s" }}>
          <div className="bento-badge terminal-badge">⌨️ CONSOLA DE AUDITORÍA</div>
          <div className="terminal-header">
            <div className="terminal-dots">
              <span className="dot red"></span>
              <span className="dot yellow"></span>
              <span className="dot green"></span>
            </div>
            <span className="terminal-title">secscan_daemon.log</span>
          </div>
          <div className="terminal-body" id="console-logs-container">
            {consoleLogs.map((log, i) => (
              <div key={i} className="terminal-line">
                <span className="terminal-prompt">$</span> {log}
              </div>
            ))}
          </div>
        </div>

        {/* PANEL 3: NETWORK SWITCHER / SELECTOR DE REDES (MEDIUM CARD) */}
        <div className="bento-card bento-switcher slide-up" style={{ animationDelay: "0.1s" }}>
          <div className="bento-badge switcher-badge">🔄 INTERCAMBIADOR DE RED</div>
          <h3 className="bento-card-title-sm">Redes y Escaneos Históricos</h3>
          <p className="bento-card-desc-sm">
            Alterna entre las redes escaneadas en tu historial para examinar topologías de extensores y equipos.
          </p>

          <div className="network-switcher-list">
            {historyList.length > 0 ? (
              historyList.map((scan, i) => (
                <div 
                  key={i} 
                  className="network-switcher-item"
                  onClick={() => navigate(`/history/${scan.scan_id}`, { state: { defaultView: "arbol" } })}
                >
                  <div className="network-item-left" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span className="network-network-icon" style={{ fontSize: '20px' }}>🌐</span>
                    <div className="network-details" style={{ display: 'flex', flexDirection: 'column' }}>
                      <span className="network-item-name">Red {scan.target_ip || "Auto"}</span>
                      <span className="network-item-meta">{scan.created_at?.split("T")[0] || "Fecha N/A"}</span>
                    </div>
                  </div>
                  <div className="network-badges" style={{ display: 'flex', gap: '8px', fontSize: '12px' }}>
                    <span className="network-badge-devices" style={{ background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px' }}>
                      👥 {scan.devices_found || 0}
                    </span>
                    <span className="network-badge-cves" style={{ background: 'rgba(255,51,102,0.1)', color: 'var(--accent-red)', padding: '2px 6px', borderRadius: '4px' }}>
                      🛡️ {scan.vulnerabilidades_found || 0}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="network-switcher-placeholder">
                No hay escaneos anteriores en la base de datos.
              </div>
            )}
          </div>
        </div>

        {/* PANEL 4: ESCANEO PASIVO EXPLICATIVO (MEDIUM CARD) */}
        <div className="bento-card bento-passive-info slide-up" style={{ animationDelay: "0.15s" }}>
          <div className="bento-badge passive-badge">🤫 ESCANEO PASIVO</div>
          <h3 className="bento-card-title-sm">¿Cómo funciona?</h3>
          <p className="bento-card-desc-sm" style={{ marginBottom: "16px" }}>
            El escaneo pasivo es **100% silencioso e indetectable** para sistemas de detección de intrusos (IDS) corporativos.
          </p>
          <ul className="passive-info-list">
            <li className="passive-info-item">
              <span>🔒</span>
              <div>
                <strong>Cero Inyección de Paquetes:</strong> No envía pings sweep ni escanea puertos de forma agresiva.
              </div>
            </li>
            <li className="passive-info-item">
              <span>📝</span>
              <div>
                <strong>Caché ARP Local:</strong> Lee la tabla de traducción de direcciones IP/MAC ya almacenada en tu sistema.
              </div>
            </li>
            <li className="passive-info-item">
              <span>⚡</span>
              <div>
                <strong>Máxima Velocidad:</strong> Completa el mapa y registra los equipos en menos de 2 segundos.
              </div>
            </li>
          </ul>
        </div>

        {/* PANEL 5: ESCANEO ESPECÍFICO / TARGET CIDR (SMALL CARD) */}
        <div className="bento-card bento-target slide-up" style={{ animationDelay: "0.2s" }}>
          <div className="bento-badge target-badge">🎯 OBJETIVO ESPECÍFICO</div>
          <h3 className="bento-card-title-sm">Escanear Objetivo</h3>
          <p className="bento-card-desc-sm" style={{ marginBottom: "14px" }}>
            Audita una IP única o un rango de subred CIDR (ej: 192.168.1.1 o 192.168.1.0/24).
          </p>
          
          <div className="quick-input-group">
            <input 
              type="text" 
              placeholder="Ej: 192.168.18.33"
              className="quick-input"
              value={rangeIp}
              onChange={(e) => setRangeIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleRangeScan()}
            />
            <button 
              className="quick-input-btn"
              onClick={handleRangeScan}
              disabled={!rangeIp.trim() || bgTaskActive}
            >
              Auditar
            </button>
          </div>
        </div>

        {/* PANEL 6: HISTORIAL GENERAL (SMALL CARD) */}
        <div 
          className="history-quicklink slide-up" 
          style={{ animationDelay: "0.25s" }}
          onClick={() => navigate("/history")}
        >
          <div className="history-quicklink-text">
            <div className="history-quicklink-title">📊 Ver Auditorías Históricas</div>
            <div className="history-quicklink-desc">
              Accede al panel completo con todas las bitácoras históricas y mapas de red anteriores.
            </div>
          </div>
          <div className="history-quicklink-arrow">→</div>
        </div>

      </div>

      {nmapMissing && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>⚙️</div>
            <h2 style={{ color: 'var(--accent-red)' }}>Motor Nmap Ausente</h2>
            <p style={{ margin: '12px 0 24px' }}>
              SecScan detectó que esta máquina no tiene el motor forense Nmap. 
              El instalador autónomo puede solucionarlo en 5 segundos sin tu intervención.
            </p>
            
            {installingNmap ? (
              <div style={{ padding: '20px' }}>
                <div className="scanning-spinner" style={{ margin: '0 auto 20px', width: '40px', height: '40px' }}></div>
                <p style={{ color: 'var(--accent-cyan)' }}>Descargando e inyectando binarios nativos...</p>
              </div>
            ) : (
              <div className="modal-buttons" style={{ justifyContent: 'center' }}>
                <button className="btn btn-ghost" onClick={() => setNmapMissing(false)}>Cancelar</button>
                <button className="btn btn-primary" onClick={handleInstallNmap}>
                  📥 Instalar Motor Automáticamente
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}


/* ========== RESULTS (Escaneo Específico) ========== */
function Results() {
  const navigate = useNavigate();
  const locationState = window.history.state?.usr;

  if (!locationState || !locationState.data) {
    navigate("/");
    return null;
  }

  const { data, tipo } = locationState;
  const resultados = data.resultados || [];

  const allVulns = [];
  resultados.forEach((r) => {
    const detalle = r.detalle || {};
    const puertos = detalle.puertos_abiertos || [];
    puertos.forEach((p) => {
      (p.vulnerabilidades || []).forEach((v) => {
        allVulns.push({
          ...v,
          puerto: p.puerto,
          servicio: p.servicio,
          version: p.version,
          ip: detalle.ip,
        });
      });
    });
  });

  allVulns.sort((a, b) => (b.score || 0) - (a.score || 0));

  const totalDevices = data.total_dispositivos || 0;
  const totalPorts = resultados.reduce((s, r) => s + (r.puertos_encontrados || 0), 0);
  const totalVulns = allVulns.length;

  const getSeverityClass = (sev) => {
    if (!sev || sev === "No disponible") return "severity-unknown";
    return `severity-${sev.toLowerCase()}`;
  };

  const getScoreColor = (score) => {
    if (score >= 9.0) return "#ff4757"; // Crítico
    if (score >= 7.0) return "#ffa502"; // Alto
    if (score >= 4.0) return "#eccc68"; // Medio
    return "#7bed9f"; // Bajo
  };

  return (
    <div className="page-container fade-in">
      <button className="btn btn-back" onClick={() => navigate("/")}>
        ← Volver al Inicio
      </button>

      <div className="results-header">
        <h1>Resultados del Escaneo</h1>
        <p>Tipo: {tipo}</p>
      </div>

      <div className="results-summary">
        <div className="summary-card slide-up">
          <div className="summary-card-label">Dispositivos</div>
          <div className="summary-card-value cyan">{totalDevices}</div>
        </div>
        <div className="summary-card slide-up" style={{ animationDelay: "0.1s" }}>
          <div className="summary-card-label">Puertos Abiertos</div>
          <div className="summary-card-value green">{totalPorts}</div>
        </div>
        <div className="summary-card slide-up" style={{ animationDelay: "0.2s" }}>
          <div className="summary-card-label">Vulnerabilidades</div>
          <div className="summary-card-value red">{totalVulns}</div>
        </div>
      </div>

      {allVulns.length > 0 ? (
        <div className="vuln-list">
          {allVulns.map((v, i) => (
            <div key={i} className={`vuln-card slide-up ${getSeverityClass(v.severidad)}`} style={{ animationDelay: `${i * 0.05}s` }}>
              <div className="vuln-score">
                <div className="vuln-score-number" style={{ color: getScoreColor(v.score || 0) }}>
                  {v.score ? v.score.toFixed(1) : "—"}
                </div>
                <span className="vuln-score-label" style={{ background: getScoreColor(v.score || 0), color: '#000' }}>
                  {v.severidad || "N/A"}
                </span>
              </div>
              <div className="vuln-port">
                <div className="vuln-port-number">:{v.puerto}</div>
                <div className="vuln-port-service">{v.servicio}</div>
                <div className="vuln-port-ip">{v.ip}</div>
              </div>
              <div className="vuln-info">
                <div className="vuln-cve-id">{v.cve_id}</div>
                <div className="vuln-description">{v.descripcion}</div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-state-icon">🛡️</div>
          <p>No se encontraron vulnerabilidades con versión detectable en este escaneo.</p>
        </div>
      )}
    </div>
  );
}

/* ========== HISTORIAL ========== */
function Historial() {
  const navigate = useNavigate();
  const location = useLocation();
  const { scanId } = useParams();
  const { getToken } = useAuth();
  const [devices, setDevices] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [topology, setTopology] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [vista, setVista] = useState(location.state?.defaultView || "lista");
  const [scanLogs, setScanLogs] = useState([]);

  const loadData = useCallback(async () => {
    try {
      const token = await getToken();
      let devs = [];
      let vuls = [];
      let topo = null;
      let status = "completed";
      
      if (scanId) {
        const [data, detailsData] = await Promise.all([
          getScanDevices(scanId, token),
          getScanDetails(scanId, token)
        ]);
        devs = data.devices || [];
        if (detailsData.status === "ok" && detailsData.details) {
           topo = detailsData.details.topology;
           status = detailsData.details.status || "completed";
           if (detailsData.details.logs) {
             setScanLogs(detailsData.details.logs);
           }
        }
      } else {
        // Fallback al legacy
        const devData = await getDevices(token);
        devs = devData.dispositivos || [];
      }

      // Extraer vulnerabilidades de los devices
      devs.forEach(d => {
        (d.puertos_abiertos || []).forEach(p => {
          (p.vulnerabilidades || []).forEach(v => {
            vuls.push({
              ...v,
              puerto: p.puerto,
              servicio: p.servicio,
              version: p.version,
              ip: d.ip
            });
          });
        });
      });
      
      vuls.sort((a, b) => (b.score || 0) - (a.score || 0));

      setDevices(devs);
      setVulns(vuls);
      setTopology(topo);
      setIsProcessing(status === "processing");
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [scanId, getToken]);

  useEffect(() => {
    loadData();
    
    // Polling si el escaneo an est en procesamiento (deep-scans corriendo en background)
    let intervalId;
    if (isProcessing) {
      intervalId = setInterval(() => {
        loadData();
      }, 5000);
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [loadData, isProcessing]);

  const getScoreColor = (score) => {
    if (score >= 9.0) return "#ff4757"; // Crítico
    if (score >= 7.0) return "#ffa502"; // Alto
    if (score >= 4.0) return "#eccc68"; // Medio
    return "#7bed9f"; // Bajo
  };

  const scrollToVuln = (ip) => {
    const els = document.querySelectorAll(`[id^="vuln-${ip}-"]`);
    if (els.length > 0) {
      els[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
      els.forEach(el => {
        el.style.transition = 'all 0.3s ease';
        el.style.transform = 'scale(1.03)';
        el.style.borderColor = 'var(--accent-red)';
        el.style.boxShadow = '0 0 20px var(--accent-red-dim)';
        setTimeout(() => {
          el.style.transform = '';
          el.style.borderColor = '';
          el.style.boxShadow = '';
        }, 1500);
      });
    }
  };

  if (loading) {
    return (
      <div className="page-container fade-in">
        <button className="btn btn-back" onClick={() => navigate("/history")}>
          ← Volver
        </button>
        <div className="scanning-spinner" style={{ margin: "40px auto", width: "40px", height: "40px" }} />
      </div>
    );
  }

  return (
    <div className="page-container fade-in">
      <div className="historial-header">
        <button className="btn btn-back" onClick={() => navigate("/history")}>
          ← Volver
        </button>
        <h1>Detalles del Escaneo</h1>
        <p>Datos almacenados en Firebase Firestore</p>
      </div>

      <div className="results-summary">
        <div className="summary-card">
          <div className="summary-card-label">Dispositivos Auditados</div>
          <div className="summary-card-value cyan">{devices?.length || 0}</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">CVEs Detectados</div>
          <div className="summary-card-value red">{vulns?.length || 0}</div>
        </div>
      </div>

      {/* ===== TOGGLE VISTA ===== */}
      <div className="view-toggle">
        <button
          className={`view-toggle-btn${vista === "lista" ? " active" : ""}`}
          onClick={() => setVista("lista")}
        >
          ☰ Vista Lista
        </button>
        <button
          className={`view-toggle-btn${vista === "arbol" ? " active" : ""}`}
          onClick={() => setVista("arbol")}
        >
          🌳 Vista Árbol
        </button>
        <button
          className={`view-toggle-btn${vista === "consola" ? " active" : ""}`}
          onClick={() => setVista("consola")}
        >
          ⌨️ Consola
        </button>
      </div>

      {/* ===== VISTA CONSOLA ===== */}
      {vista === "consola" && (
        <div className="bento-card bento-terminal slide-up" style={{ marginTop: "20px" }}>
          <div className="bento-badge terminal-badge">⌨️ CONSOLA DE AUDITORÍA</div>
          <div className="terminal-header">
            <div className="terminal-dots">
              <span className="dot red"></span>
              <span className="dot yellow"></span>
              <span className="dot green"></span>
            </div>
            <span className="terminal-title">secscan_daemon.log</span>
          </div>
          <div className="terminal-body" id="historial-console-container" style={{ minHeight: "500px", maxHeight: "800px" }}>
            {scanLogs.length > 0 ? (
              scanLogs.map((log, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-prompt">$</span> {log}
                </div>
              ))
            ) : (
              <div className="terminal-line" style={{ color: "var(--text-gray)" }}>
                No hay logs registrados para esta auditoría.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ===== VISTA ÁRBOL ===== */}
      {vista === "arbol" && (
        <NetworkTree 
          devices={devices} 
          topology={topology} 
          onVulnClick={(ip) => {
            if (document.fullscreenElement) {
              document.exitFullscreen().catch(err => console.log(err));
            }
            setVista("lista");
            setTimeout(() => scrollToVuln(ip), 150);
          }}
        />
      )}

      {/* ===== VISTA LISTA (existente) ===== */}
      {vista === "lista" && (
        <>
      <h2 style={{ marginBottom: 20, fontSize: 20 }}>Dispositivos</h2>
      {devices && devices.length > 0 ? (
        <div className="device-list" style={{ marginBottom: 40 }}>
          {devices.map((d, i) => (
            <div 
              key={i} 
              className={`device-card slide-up ${d.es_nuevo ? 'device-new-highlight' : ''}`} 
              style={{ 
                animationDelay: `${i * 0.05}s`,
                cursor: d.total_vulnerabilidades > 0 ? 'pointer' : 'default'
              }}
              onClick={() => d.total_vulnerabilidades > 0 && scrollToVuln(d.ip)}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <div className="device-ip">{d.ip}</div>
                  {d.hostname
                    ? <span style={{ color: 'var(--accent-cyan)', fontSize: '0.85rem', padding: '2px 8px', background: 'rgba(100, 255, 218, 0.1)', borderRadius: '4px', fontWeight: 600 }}>
                        {getDeviceIcon(d)} {d.hostname}
                      </span>
                    : <span style={{ color: '#555', fontSize: '0.8rem', padding: '2px 8px', background: 'rgba(255,255,255,0.03)', borderRadius: '4px', fontStyle: 'italic' }}>
                        {getDeviceIcon(d)} Dispositivo Oculto
                      </span>
                  }
                  {d.es_nuevo && <span className="badge-new">🚨 NUEVO</span>}
                </div>
                <div className="device-mac">
                  {d.fabricante && d.fabricante !== "Desconocido" ? `⚙️ Fabricante: ${d.fabricante}` : `MAC: ${d.mac}`}
                </div>
              </div>
              <div className="device-stat">
                <div className="device-stat-value" style={{ color: getScoreColor(d.max_score || 0) }}>
                  {d.max_score ? d.max_score.toFixed(1) : "0.0"}
                </div>
                <div className="device-stat-label">Riesgo Máx</div>
              </div>
              <div className="device-stat">
                <div className="device-stat-value red">{d.total_vulnerabilidades || 0}</div>
                <div className="device-stat-label">CVEs</div>
              </div>
              <div className="device-date">
                <div>Auditoría: {d.fecha_auditoria?.split("T")[0] || "—"}</div>
                {d.primera_conexion && (
                  <div style={{ fontSize: '11px', color: '#64ffda', marginTop: '4px', fontWeight: 'bold' }}>
                    Entró: {d.primera_conexion.replace("T", " ").substring(0, 19)}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-state-icon">📭</div>
          <p>No hay dispositivos en este escaneo.</p>
        </div>
      )}
        </>
      )}

      {vista === "lista" && vulns && vulns.length > 0 && (
        <>
          <h2 style={{ marginBottom: 20, fontSize: 20 }}>Vulnerabilidades Detectadas</h2>
          <div className="vuln-list">
            {vulns.map((v, i) => (
              <div 
                key={i} 
                id={`vuln-${v.ip}-${i}`}
                className={`vuln-card slide-up severity-${v.severidad?.toLowerCase() || 'unknown'}`}
              >
                <div className="vuln-score">
                  <div className="vuln-score-number" style={{ color: getScoreColor(v.score || 0) }}>
                    {v.score ? v.score.toFixed(1) : "—"}
                  </div>
                  <span className="vuln-score-label" style={{ background: getScoreColor(v.score || 0), color: '#000' }}>
                    {v.severidad || "N/A"}
                  </span>
                </div>
                <div className="vuln-port">
                  <div className="vuln-port-number">:{v.puerto}</div>
                  <div className="vuln-port-service">{v.servicio}</div>
                  <div className="vuln-port-ip">{v.ip}</div>
                </div>
                <div className="vuln-info">
                  <div className="vuln-cve-id">{v.cve_id}</div>
                  <div className="vuln-description">{v.descripcion}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/* ========== APP ========== */
function App() {
  return (
    <AuthProvider>
      <Router>
        <Navbar />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <Home />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/results" 
            element={
              <ProtectedRoute>
                <Results />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/history" 
            element={
              <ProtectedRoute>
                <ScanHistoryPage />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/history/:scanId" 
            element={
              <ProtectedRoute>
                <Historial />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/historial" 
            element={
              <ProtectedRoute>
                <Historial />
              </ProtectedRoute>
            } 
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
