import { useState, useEffect, useCallback } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useNavigate,
  useParams,
  useLocation
} from "react-router-dom";
import { triggerN8nScan, deepScan, getDevices, getVulnerabilities, checkHealth, installNmap, getScanDevices, getScanDetails } from "./services/api";
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

  return (
    <nav className="navbar">
      <a href="/" className="navbar-logo">
        <div className="navbar-logo-icon">SS</div>
        <div className="navbar-logo-text">
          Sec<span>Scan</span>
        </div>
      </a>
      
      <div className="navbar-right">
        <div className="navbar-status">
          <div className="navbar-status-dot" />
          Motor Activo
        </div>

        {user && (
          <div className="user-profile">
            <img 
              src={user.photoURL || "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y"} 
              alt={user.displayName} 
              className="user-avatar" 
              referrerPolicy="no-referrer"
            />
            <div className="user-info">
              <span className="user-name">{user.displayName}</span>
              <button onClick={logout} className="btn-logout">Cerrar Sesión</button>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}

/* ========== HOME ========== */
function Home() {
  const navigate = useNavigate();
  const [scanning, setScanning] = useState(false);
  const [bgTaskActive, setBgTaskActive] = useState(false);
  const [scanMsg, setScanMsg] = useState("");
  const [showRangeModal, setShowRangeModal] = useState(false);
  const [rangeIp, setRangeIp] = useState("");
  const [devicesFound, setDevicesFound] = useState(0);
  const [pollCount, setPollCount] = useState(0);
  const [nmapMissing, setNmapMissing] = useState(false);
  const [installingNmap, setInstallingNmap] = useState(false);

  const { getToken } = useAuth();

  // (El polling ahora se maneja internamente en handleFullScan para trackear el progreso real)

  const handleFullScan = async () => {
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
    setPollCount(0);
    setScanMsg("Conectando con el motor de escaneo...");
    try {
      const token = await getToken();
      const scanId = crypto.randomUUID();

      const scanResult = await triggerN8nScan("auto", token, scanId);
      
      if (scanResult.modo === "n8n") {
        setScanMsg("⚡ Modo Turbo (n8n) — Escaneando tu red en paralelo...");
      } else if (scanResult.modo === "directo") {
        setScanMsg(`✅ Modo Directo — ${scanResult.mensaje}`);
      } else {
        setScanMsg("Escaneando tu red. Esperando resultados...");
      }

      setTimeout(async () => {
        const maxPolls = 150; // 150 * 3s = 7.5 minutos de timeout máximo (necesario por escaneos -T2)
        let polls = 0;
        const checkResults = setInterval(async () => {
          polls++;
          try {
            const token = await getToken();
            const res = await getScanDetails(scanId, token);
            if (res.status === "ok" && res.details) {
              const { devices_found = 0, total_targets = 1 } = res.details;
              setDevicesFound(devices_found);
              
              setScanMsg(`n8n trabajando... (${devices_found} / ${total_targets}) dispositivos auditados`);

              // Condición de éxito: Llegamos al total de targets descubiertos
              if (devices_found >= total_targets && polls >= 3) {
                clearInterval(checkResults);
                setScanning(false);
                setBgTaskActive(false);
                navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });
              }
            }

            // Timeout de seguridad si se queda trabado (ej. n8n falló a la mitad)
            if (polls >= maxPolls) {
              clearInterval(checkResults);
              setScanning(false);
              setBgTaskActive(false);
              navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });
            }
          } catch (e) {
             console.error("Error polling scan progress", e);
          }
        }, 3000);
      }, 5000);
    } catch (err) {
      setScanning(false);
      setBgTaskActive(false);
      alert("Error: ¿Está n8n activo en localhost:5678 con el workflow activado?");
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

  const handleHistorial = () => {
    navigate("/history");
  };

  const handleHideProgress = () => {
    setScanning(false);
    setScanMsg("");
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
          Plataforma de ciberseguridad para PyMEs. Escanea tu red, detecta servicios expuestos y cruza
          automáticamente con la base de datos CVE mundial.
        </p>
      </div>

      <div className="action-cards">
        <div className="action-card slide-up" onClick={handleFullScan}>
          <div className="action-card-icon scan">🛰️</div>
          <h3>Escaneo General</h3>
          <p>
            Descubre todos los dispositivos conectados a tu red y analiza sus vulnerabilidades
            automáticamente con n8n.
          </p>
        </div>

        <div className="action-card slide-up" onClick={() => setShowRangeModal(true)} style={{ animationDelay: "0.1s" }}>
          <div className="action-card-icon target">🎯</div>
          <h3>Escaneo Específico</h3>
          <p>
            Ingresa una IP o rango personalizado para auditar un objetivo
            particular de tu infraestructura.
          </p>
        </div>

        <div className="action-card slide-up" onClick={handleHistorial} style={{ animationDelay: "0.2s" }}>
          <div className="action-card-icon history">📊</div>
          <h3>Historial</h3>
          <p>
            Consulta los resultados de escaneos anteriores almacenados
            en la nube de Firebase.
          </p>
        </div>
      </div>

      {scanning && (
        <div className="scanning-overlay">
          <div className="scanning-spinner" />
          <div className="scanning-text">Escaneando Red...</div>
          <div className="scanning-sub">{scanMsg}</div>
          {devicesFound > 0 && (
            <div className="scanning-sub" style={{ marginTop: 8, color: "var(--accent-green)" }}>
              🟢 {devicesFound} dispositivos detectados hasta ahora
            </div>
          )}
          <button
            className="btn btn-ghost"
            style={{ marginTop: 24 }}
            onClick={handleHideProgress}
          >
            Ocultar progreso
          </button>
        </div>
      )}

      {showRangeModal && (
        <div className="modal-overlay" onClick={() => setShowRangeModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>🎯 Escaneo Específico</h2>
            <p>
              Ingresa la IP del equipo que deseas auditar (ej: 192.168.1.1)
              o un rango CIDR (ej: 192.168.1.0/24).
            </p>
            <input
              className="modal-input"
              type="text"
              placeholder="192.168.1.1"
              value={rangeIp}
              onChange={(e) => setRangeIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleRangeScan()}
              autoFocus
            />
            <div className="modal-buttons">
              <button className="btn btn-ghost" onClick={() => setShowRangeModal(false)}>
                Cancelar
              </button>
              <button className="btn btn-primary" onClick={handleRangeScan} disabled={!rangeIp.trim()}>
                Escanear
              </button>
            </div>
          </div>
        </div>
      )}
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
      </div>

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
