import { Home as HomeIcon, BarChart, LogOut, Shield, Crosshair, Flame, Radio, Globe, Monitor, Plug, Folder, Clock, AlertTriangle, Activity, Rocket, EyeOff, Zap } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useNavigate,
  useParams,
  useLocation
} from "react-router-dom";
import { triggerN8nScan, deepScan, getDevices, getVulnerabilities, checkHealth, installNmap, getScanDevices, getScanDetails, getScanHistory, getWifiNetworks, connectWifi } from "./services/api";
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
                <span className="sidebar-user-role"><Shield size={16} className="inline-icon" />  Auditor de Redes</span>
              </div>
            </div>

            <div className="sidebar-menu">
              <div className="sidebar-menu-section-title">Navegación</div>
              <a href="/" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>
                <HomeIcon size={18} className="inline-icon" />  Inicio Dashboard
              </a>
              <a href="/history" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>
                <BarChart size={18} className="inline-icon" />  Historial de Auditorías
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
                <LogOut size={18} className="inline-icon" />  Cerrar Sesión
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

  const [targetType, setTargetType] = useState("auto"); // "auto" | "custom"
  const [customTarget, setCustomTarget] = useState("");

  const [switcherTab, setSwitcherTab] = useState("history"); // "history" | "wifi"
  const [wifiNetworks, setWifiNetworks] = useState([]);
  const [scanningWifi, setScanningWifi] = useState(false);
  const [selectedWifi, setSelectedWifi] = useState(null);
  const [wifiPassword, setWifiPassword] = useState("");
  const [connectingWifi, setConnectingWifi] = useState(false);

  const handleScanWifi = async () => {
    setScanningWifi(true);
    try {
      const token = await getToken();
      const res = await getWifiNetworks(token);
      if (res.status === "ok") {
        setWifiNetworks(res.networks);
      } else {
        console.error("Error al escanear WiFi:", res.detail);
      }
    } catch (e) {
      console.error("Error cargando WiFi", e);
    }
    setScanningWifi(false);
  };

  const handleConnectWifi = async () => {
    if (!selectedWifi) return;
    setConnectingWifi(true);
    try {
      const token = await getToken();
      const res = await connectWifi(selectedWifi.ssid, wifiPassword, token);
      if (res.status === "ok") {
        setConsoleLogs(prev => [...prev, `[OK] Conectando a '${selectedWifi.ssid}'... La red cambiará en unos segundos.`]);
        setSelectedWifi(null);
        setWifiPassword("");
      } else {
        setConsoleLogs(prev => [...prev, `[ERR] Error al conectar: ${res.detail}`]);
      }
    } catch (e) {
      setConsoleLogs(prev => [...prev, "[ERR] Error crítico conectando a la red WiFi."]);
    }
    setConnectingWifi(false);
  };

  useEffect(() => {
    if (switcherTab === "wifi") {
      handleScanWifi();
    }
  }, [switcherTab]);

  const [historyList, setHistoryList] = useState([]);
  const [consoleLogs, setConsoleLogs] = useState([
    "[SYS] SecScan CLI v1.2.0 - Motor de Auditoría y Redes Activo.",
    "[SYS] Elige un método de escaneo en los paneles interactivos del Bento Grid para inicializar...",
    "[SEC] Listo para monitoreo continuo en subredes locales."
  ]);

  const { getToken } = useAuth();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const token = await getToken();
        const data = await getScanHistory(token);
        if (data.status === "ok" && data.scans) {
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

    const target = targetType === "auto" ? "auto" : customTarget.trim();
    if (targetType === "custom" && !target) {
      alert("Por favor, ingresa un rango de red o dirección IP válida.");
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
    setScanMsg(passiveScan ? "Inicializando escaneo pasivo indetectable..." : `Conectando con el motor de escaneo activo en ${target}...`);

    setConsoleLogs([`[SYS] SecScan Daemon - Conectando con el motor backend para auditar ${target}...`]);

    try {
      const token = await getToken();
      const scanId = crypto.randomUUID();

      const scanResult = await triggerN8nScan(target, token, scanId, passiveScan);
      
      if (passiveScan) {
        setScanMsg("[SEC] Modo Pasivo (ARP Caché) — Leyendo memoria local...");
      } else if (scanResult.modo === "n8n") {
        setScanMsg("[RUN] Modo Turbo (n8n) — Escaneando tu red en paralelo...");
      } else {
        setScanMsg("Escaneando tu red. Esperando resultados...");
      }

      const scrollToBottom = () => {
        setTimeout(() => {
          const el = document.getElementById("console-logs-container");
          if (el) el.scrollTop = el.scrollHeight;
        }, 50);
      };

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
              
              if (logs.length > 0) {
                setConsoleLogs(logs);
                scrollToBottom();
              }
              
              setDevicesFound(devices_found);
              
              if (!passiveScan && status !== "completed") {
                setScanMsg(`Auditando puertos... (${devices_found} / ${total_targets || '?'}) dispositivos listos`);
              }

              if (status === "completed") {
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
      if (err.code === "SIN_INTERNET") {
        alert("⚠️ Sin conexión a internet. El escaneo requiere conexión activa para registrar los resultados en la nube. Por favor, verifica tu red e inténtalo de nuevo.");
      } else {
        alert("Error de conexión. ¿El backend está encendido?");
      }
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

      <div className="bento-grid">
        
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
              <Rocket size={18} className="inline-icon" style={{marginRight: '8px'}} /> Iniciar Escaneo Activo
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
            {consoleLogs.map((log, i) => {
              let color = "var(--text-secondary)";
              if (log.includes("[OK]") || log.includes("[ABIERTO]"))       color = "var(--green-400)";
              else if (log.includes("[BLOQUEADO]") || log.includes("[ERROR]")) color = "var(--red-400)";
              else if (log.includes("[ALERTA]"))                            color = "var(--yellow-400)";
              else if (log.includes("[HOST]") || log.includes("[DEEP-SCAN]")) color = "var(--purple-400)";
              return (
                <div key={i} className="terminal-line" style={{ color }}>
                  <span className="terminal-prompt">$</span> {log}
                </div>
              );
            })}
          </div>
        </div>

        <div className="bento-card bento-switcher slide-up" style={{ animationDelay: "0.1s", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div className="bento-badge switcher-badge">🔄 INTERCAMBIADOR DE RED</div>
          <h3 className="bento-card-title-sm">Redes y Escaneos</h3>
          <p className="bento-card-desc-sm">
            Alterna entre las redes escaneadas en tu historial o cambia la conexión Wi-Fi física de esta máquina auditora.
          </p>

          <div className="switcher-tabs" style={{ display: "flex", gap: "8px", margin: "12px 0" }}>
            <button
              type="button"
              className={`switcher-tab-btn ${switcherTab === "history" ? "active" : ""}`}
              style={{
                flex: 1,
                padding: "8px 10px",
                borderRadius: "8px",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
                border: "1px solid var(--border-subtle)",
                background: switcherTab === "history" ? "var(--purple-dim)" : "var(--bg-surface)",
                color: switcherTab === "history" ? "var(--purple-400)" : "var(--text-secondary)",
                borderColor: switcherTab === "history" ? "var(--purple-border)" : "var(--border-subtle)",
                transition: "all 0.2s ease"
              }}
              onClick={() => setSwitcherTab("history")}
            >
              <BarChart size={18} className="inline-icon" />  Historial
            </button>
            <button
              type="button"
              className={`switcher-tab-btn ${switcherTab === "wifi" ? "active" : ""}`}
              style={{
                flex: 1,
                padding: "8px 10px",
                borderRadius: "8px",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
                border: "1px solid var(--border-subtle)",
                background: switcherTab === "wifi" ? "var(--cyan-dim)" : "var(--bg-surface)",
                color: switcherTab === "wifi" ? "var(--cyan-400)" : "var(--text-secondary)",
                borderColor: switcherTab === "wifi" ? "var(--cyan-border)" : "var(--border-subtle)",
                transition: "all 0.2s ease"
              }}
              onClick={() => setSwitcherTab("wifi")}
            >
              📶 Redes Wi-Fi
            </button>
          </div>

          {switcherTab === "history" ? (
            <div className="network-switcher-list" style={{ overflowY: "auto", flex: 1 }}>
              {(() => {
                const realScans = historyList.filter(s => s.target_ip && s.target_ip.trim() !== "");
                return realScans.length > 0 ? (
                  realScans.map((scan, i) => (
                    <div
                      key={i}
                      className="network-switcher-item"
                      onClick={() => navigate(`/history/${scan.scan_id}`, { state: { defaultView: "arbol" } })}
                      style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
                    >
                      <span className="network-network-icon" style={{ fontSize: '18px' }}><Globe size={18} className="inline-icon" /> </span>
                      <span className="network-item-name">{scan.target_ip}</span>
                    </div>
                  ))
                ) : null;
              })()}
            </div>
          ) : (
            <div className="network-switcher-list" style={{ overflowY: "auto", flex: 1 }}>
              {scanningWifi ? (
                <div style={{ padding: "30px 10px", textAlign: "center" }}>
                  <div className="bento-spinner-sm" style={{ margin: "0 auto 12px" }} />
                  <p style={{ color: "var(--cyan-400)", fontSize: "12px" }}>Buscando redes inalámbricas...</p>
                </div>
              ) : (
                <>
                  {wifiNetworks.map((net, i) => {
                    const sig = net.signal || 0;
                    const bars = sig >= 80 ? 4 : sig >= 60 ? 3 : sig >= 40 ? 2 : sig >= 20 ? 1 : 0;
                    return (
                      <div 
                        key={i} 
                        className="network-switcher-item"
                        onClick={() => setSelectedWifi(net)}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <span className="network-network-icon" style={{ fontSize: '20px' }}>📶</span>
                          <span className="network-item-name">{net.ssid}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: '16px', marginRight: '4px' }}>
                          {[1,2,3,4].map(b => (
                            <div key={b} style={{
                              width: '4px',
                              height: `${4 + b * 3}px`,
                              borderRadius: '1px',
                              background: b <= bars
                                ? (bars >= 4 ? 'var(--green-400)' : bars >= 3 ? 'var(--cyan-400)' : bars >= 2 ? 'var(--yellow-400)' : 'var(--accent-red)')
                                : 'rgba(255,255,255,0.12)',
                              transition: 'background 0.3s'
                            }} />
                          ))}
                        </div>
                      </div>
                    );
                  })}
                  {wifiNetworks.length === 0 && (
                    <div className="network-switcher-placeholder">
                      No se encontraron redes Wi-Fi visibles.
                    </div>
                  )}
                  <button 
                    className="bento-btn bento-btn-secondary" 
                    style={{ padding: "8px", fontSize: "12px", marginTop: "12px" }}
                    onClick={handleScanWifi}
                  >
                    🔄 Escanear Redes de Nuevo
                  </button>
                </>
              )}
            </div>
          )}
        </div>

        <div className="bento-card bento-passive-info slide-up" style={{ animationDelay: "0.15s", padding: "20px" }}>
          <div className="bento-badge passive-badge"><EyeOff size={14} className="inline-icon" style={{marginRight: '4px'}} /> ESCANEO PASIVO</div>
          <h3 className="bento-card-title-sm" style={{ fontSize: "15px" }}>¿Cómo funciona?</h3>
          <p className="bento-card-desc-sm" style={{ marginBottom: "12px", fontSize: "12px", lineHeight: "1.4" }}>
            El escaneo pasivo es **silencioso e indetectable** para sistemas de seguridad (IDS).
          </p>
          <ul className="passive-info-list" style={{ gap: "10px" }}>
            <li className="passive-info-item" style={{ fontSize: "12px" }}>
              <span style={{ fontSize: "14px" }}>🔒</span>
              <div>
                <strong>Sin Inyección:</strong> No envía paquetes ni escanea puertos de forma activa.
              </div>
            </li>
            <li className="passive-info-item" style={{ fontSize: "12px" }}>
              <span style={{ fontSize: "14px" }}>📝</span>
              <div>
                <strong>Caché ARP:</strong> Lee la tabla local de direcciones IP/MAC del sistema.
              </div>
            </li>
            <li className="passive-info-item" style={{ fontSize: "12px" }}>
              <span style={{ fontSize: "14px" }}><Zap size={14} className="inline-icon" /></span>
              <div>
                <strong>Veloz:</strong> Completa el mapa y registra los equipos en menos de 2s.
              </div>
            </li>
          </ul>
        </div>

        <div className="bento-card bento-target slide-up" style={{ animationDelay: "0.2s" }}>
          <div className="bento-badge target-badge"><Crosshair size={18} className="inline-icon" />  OBJETIVO ESPECÍFICO</div>
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

        <div 
          className="history-quicklink slide-up" 
          style={{ animationDelay: "0.25s" }}
          onClick={() => navigate("/history")}
        >
          <div className="history-quicklink-text">
            <div className="history-quicklink-title"><BarChart size={18} className="inline-icon" />  Ver Auditorías Históricas</div>
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

      {selectedWifi && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: "400px" }}>
            <div style={{ fontSize: "36px", marginBottom: "12px", textAlign: "center" }}>📶</div>
            <h3 style={{ color: "var(--cyan-400)", marginBottom: "10px", textAlign: "center" }}>
              Conectar a {selectedWifi.ssid}
            </h3>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "16px", textAlign: "center" }}>
              Seguridad: <strong>{selectedWifi.auth}</strong> | Señal: <strong>{selectedWifi.signal}%</strong>
            </p>
            
            {selectedWifi.auth.toLowerCase().includes("open") || selectedWifi.auth.toLowerCase().includes("abierta") || selectedWifi.auth.toLowerCase().includes("none") ? (
              <p style={{ fontSize: "13px", color: "var(--green-400)", marginBottom: "20px", textAlign: "center" }}>
                Esta es una red abierta. No se requiere contraseña para conectarse.
              </p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "20px" }}>
                <label style={{ fontSize: "12px", color: "var(--text-secondary)", fontWeight: "600" }}>
                  Contraseña de Red
                </label>
                <input
                  type="password"
                  placeholder="Ingresa la contraseña de la red..."
                  className="quick-input"
                  value={wifiPassword}
                  onChange={(e) => setWifiPassword(e.target.value)}
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-base)",
                    borderRadius: "8px",
                    padding: "10px 12px",
                    color: "var(--text-primary)",
                    outline: "none"
                  }}
                  onKeyDown={(e) => e.key === "Enter" && !connectingWifi && handleConnectWifi()}
                />
              </div>
            )}
            
            {connectingWifi ? (
              <div style={{ padding: "10px", textAlign: "center" }}>
                <div className="bento-spinner-sm" style={{ margin: "0 auto 10px" }} />
                <p style={{ color: "var(--cyan-400)", fontSize: "12px" }}>Enviando credenciales y conectando...</p>
              </div>
            ) : (
              <div className="modal-buttons" style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button className="btn btn-ghost" onClick={() => { setSelectedWifi(null); setWifiPassword(""); }}>
                  Cancelar
                </button>
                <button 
                  className="btn btn-primary" 
                  onClick={handleConnectWifi}
                  disabled={!(selectedWifi.auth.toLowerCase().includes("open") || selectedWifi.auth.toLowerCase().includes("abierta") || selectedWifi.auth.toLowerCase().includes("none")) && !wifiPassword.trim()}
                >
                  <Zap size={16} className="inline-icon" style={{marginRight: '6px'}} /> Conectar
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
          <div className="empty-state-icon"><Shield size={16} className="inline-icon" /> </div>
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
        const devData = await getDevices(token);
        devs = devData.dispositivos || [];
      }

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

  useEffect(() => {
    if (!loading && location.state?.autoPrint) {
      setTimeout(() => {
        window.print();
        window.history.replaceState({}, '');
      }, 800);
    }
  }, [loading, location.state]);

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
      <div className="historial-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <button className="btn btn-back" onClick={() => navigate("/history")}>
            ← Volver
          </button>
          <h1>Detalles del Escaneo</h1>
          <p>Datos almacenados en Firebase Firestore</p>
        </div>
        <button className="btn btn-primary" onClick={() => window.print()} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          🖨️ Exportar a PDF / Imprimir
        </button>
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

      {vista === "lista" && (
        <>
          <h2 className="print-section-devices" style={{ marginBottom: 20, fontSize: 20 }}>Dispositivos</h2>
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
                  {d.es_nuevo && <span className="badge-new"><AlertTriangle size={18} className="inline-icon" />  NUEVO</span>}
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
          <h2 className="print-section-vulns" style={{ marginBottom: 20, fontSize: 20 }}>Vulnerabilidades Detectadas</h2>
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
