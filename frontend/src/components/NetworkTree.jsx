import { useState, useRef, useCallback, useMemo } from "react";

/* ─── UTILIDADES ────────────────────────────────────────────── */
function isPrivateIP(ip) {
  if (!ip) return false;
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
function getSubnetPrefix(ip) { return ip ? ip.split(".").slice(0, 3).join(".") : ""; }

function chunkArray(arr, size) {
  if (!arr) return [];
  return Array.from({ length: Math.ceil(arr.length / size) }, (v, i) =>
    arr.slice(i * size, i * size + size)
  );
}

function getScoreColor(s) {
  if (!s || s === 0) return "#00ff88";
  if (s >= 9.0) return "#ff3366";
  if (s >= 7.0) return "#ff8c00";
  if (s >= 4.0) return "#ffd000";
  return "#00ff88";
}
function getRiskLabel(s) {
  if (!s || s === 0) return "SEGURO";
  if (s >= 9.0) return "CRÍTICO";
  if (s >= 7.0) return "ALTO";
  if (s >= 4.0) return "MEDIO";
  return "BAJO";
}
export function getDeviceIcon(d, routerIp = null) {
  if (routerIp && d.ip === routerIp) return "📡";

  const f = (d.fabricante || "").toLowerCase();
  const h = (d.hostname || "").toLowerCase();
  
  // Routers / APs / Switches
  if (f.includes("cisco") || f.includes("tp-link") || f.includes("netgear") || f.includes("ubiquiti") || f.includes("mikrotik") || f.includes("d-link") || f.includes("aruba") || h.includes("router") || h.includes("gateway") || h.includes("ap")) return "📡";
  
  // Smartphones & Tablets
  if (f.includes("apple") || h.includes("iphone") || h.includes("ipad")) return "🍎";
  if (f.includes("samsung") || f.includes("motorola") || f.includes("huawei") || f.includes("xiaomi") || f.includes("oppo") || f.includes("vivo") || f.includes("oneplus") || h.includes("android") || h.includes("phone")) return "📱";
  
  // TVs & Media Players
  if (f.includes("roku") || f.includes("lg electronics") || f.includes("tcl") || f.includes("hisense") || h.includes("tv") || h.includes("chromecast") || h.includes("fire") || h.includes("cast")) return "📺";
  
  // Consolas de Videojuegos
  if (f.includes("nintendo") || f.includes("sony interactive") || h.includes("xbox") || h.includes("playstation") || h.includes("switch")) return "🎮";
  
  // Cámaras / Seguridad
  if (f.includes("hikvision") || f.includes("dahua") || f.includes("axis") || h.includes("camera") || h.includes("cam") || h.includes("dvr") || h.includes("nvr")) return "📷";
  
  // Impresoras
  if (f.includes("hewlett") || f.includes("hp") || f.includes("epson") || f.includes("canon") || f.includes("brother") || h.includes("print")) return "🖨️";
  
  // IoT / Domótica
  if (f.includes("tuya") || f.includes("sonoff") || f.includes("philips") || h.includes("smart") || h.includes("iot") || h.includes("home")) return "💡";
  
  // Servidores / NAS
  if (f.includes("synology") || f.includes("qnap") || h.includes("server") || h.includes("srv") || h.includes("nas")) return "🗄️";
  
  // Laptops / PCs (Fallback)
  if (f.includes("dell") || f.includes("lenovo") || f.includes("asus") || f.includes("acer") || f.includes("msi") || h.includes("macbook") || h.includes("pc") || h.includes("desktop") || h.includes("laptop")) return "💻";
  
  // Default Desconocido
  return "💻";
}

/* ─── ÁRBOL HEURÍSTICO / TOPOLÓGICO ──────────────────────────────────────── */
function buildTree(devices, topology) {
  if (!devices?.length && !topology) return null;
  
  const bySubnet = {};
  (devices || []).forEach(d => {
    const p = getSubnetPrefix(d.ip);
    if (!bySubnet[p]) bySubnet[p] = [];
    bySubnet[p].push(d);
  });

  // Si tenemos topología real del backend (Traceroute)
  if (topology && topology.hops_privados) {
    const hops = topology.hops_privados;
    // El último hop privado es el gateway principal
    const mainHop = hops[hops.length - 1];
    // Los anteriores son extensores
    const extHops = hops.slice(0, -1);
    
    // Asignar prefijos a los hops
    const mainPrefix = mainHop ? getSubnetPrefix(mainHop.ip) : null;
    const routerIp = topology.router_principal_ip || mainHop?.ip || `${mainPrefix}.1`;

    const main = mainPrefix ? {
      prefix: mainPrefix,
      gateway: mainHop,
      devices: (bySubnet[mainPrefix] || []).filter(d => d.ip !== routerIp),
      total: (bySubnet[mainPrefix] || []).length
    } : null;

    const extensorsRaw = extHops.map((hop, i) => {
      if (hop.tipo === "invisible") {
        return {
          prefix: `invisible-${i}`,
          gateway: hop,
          devices: [],
          total: 0
        };
      }
      const p = getSubnetPrefix(hop.ip);
      return {
        prefix: p,
        gateway: hop,
        devices: (bySubnet[p] || []).filter(d => d.ip !== routerIp && d.ip !== hop?.ip),
        total: (bySubnet[p] || []).length
      };
    });

    // Agrupar hops invisibles si hay 3 o más
    const extensors = [];
    let invisibleCount = 0;
    for (let i = 0; i < extensorsRaw.length; i++) {
      if (extensorsRaw[i].gateway?.tipo === "invisible") {
        invisibleCount++;
      } else {
        if (invisibleCount > 0) {
          if (invisibleCount >= 3) {
            extensors.push({ prefix: `inv-group-${i}`, isGroup: true, count: invisibleCount, devices: [], total: 0 });
          } else {
            for (let j = 0; j < invisibleCount; j++) {
              extensors.push({ prefix: `invisible-single-${i}-${j}`, gateway: { tipo: "invisible" }, devices: [], total: 0 });
            }
          }
          invisibleCount = 0;
        }
        extensors.push(extensorsRaw[i]);
      }
    }
    if (invisibleCount > 0) {
      if (invisibleCount >= 3) {
        extensors.push({ prefix: `inv-group-end`, isGroup: true, count: invisibleCount, devices: [], total: 0 });
      } else {
        for (let j = 0; j < invisibleCount; j++) {
          extensors.push({ prefix: `invisible-single-end-${j}`, gateway: { tipo: "invisible" }, devices: [], total: 0 });
        }
      }
    }

    // Subredes huérfanas (descubiertas por Nmap pero sin hop de traceroute)
    const knownPrefixes = [mainPrefix, ...extensorsRaw.map(e => e.prefix)].filter(Boolean);
    const orphanSubnets = Object.entries(bySubnet)
      .filter(([prefix]) => !knownPrefixes.includes(prefix))
      .map(([prefix, devs]) => ({
        prefix,
        gateway: devs.find(d => d.ip === `${prefix}.1`) || { ip: `${prefix}.1`, hostname: 'Gateway Inferido' },
        devices: devs.filter(d => d.ip !== routerIp && d.ip !== `${prefix}.1`),
        total: devs.length,
      }));

    return { 
      isp: topology.router_isp, 
      main: main || orphanSubnets[0], 
      extensors: [...extensors, ...(main ? orphanSubnets : orphanSubnets.slice(1))] 
    };
  }

  // Fallback a la heurística antigua si no hay topología
  const subnets = Object.entries(bySubnet)
    .map(([prefix, devs]) => ({
      prefix,
      gateway: devs.find(d => d.ip === `${prefix}.1`) || null,
      devices: devs.filter(d => d.ip !== `${prefix}.1`),
      total: devs.length,
    }))
    .sort((a, b) => b.total - a.total);
    
  return { isp: null, main: subnets[0], extensors: subnets.slice(1) };
}

/* ─── CARD: INTERNET ────────────────────────────────────────── */
function InternetCard() {
  return (
    <div className="nt-card nt-card--internet">
      <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(0,212,255,0.3) 0%, transparent 70%)" }} />
      <div className="nt-card-icon">🌐</div>
      <div className="nt-card-label">Internet</div>
      <div className="nt-badge" style={{ background: "rgba(0,212,255,0.15)", color: "#00d4ff", border: "1px solid rgba(0,212,255,0.3)" }}>
        INTERNET
      </div>
    </div>
  );
}

/* ─── CARD: GATEWAY ─────────────────────────────────────────── */
function GatewayCard({ ip, hostname, fabricante }) {
  return (
    <div className="nt-card nt-card--gateway">
      <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(91,127,222,0.35) 0%, transparent 70%)" }} />
      <div className="nt-card-icon">🔵</div>
      <div className="nt-card-label">Router Principal</div>
      {hostname && <div className="nt-card-hostname">{hostname}</div>}
      <div className="nt-card-ip">{ip}</div>
      {fabricante && fabricante !== "Desconocido" && <div className="nt-card-fab">{fabricante}</div>}
      <div className="nt-badge" style={{ background: "rgba(91,127,222,0.2)", color: "#7b9fff", border: "1px solid rgba(91,127,222,0.4)" }}>
        GATEWAY
      </div>
    </div>
  );
}

/* ─── CARD: EXTENSOR ────────────────────────────────────────── */
function ExtensorCard({ ip, hostname, fabricante, deviceCount, nat_habilitado }) {
  return (
    <div className="nt-card nt-card--extensor">
      <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(243,156,18,0.3) 0%, transparent 70%)" }} />
      <div className="nt-card-icon">📡</div>
      <div className="nt-card-label">{hostname || "Extensor / AP"}</div>
      <div className="nt-card-ip">{ip}</div>
      {fabricante && fabricante !== "Desconocido" && <div className="nt-card-fab">{fabricante}</div>}
      <div style={{ display: "flex", gap: 6, justifyContent: "center", flexWrap: "wrap" }}>
        <div className="nt-badge" style={{ background: "rgba(243,156,18,0.15)", color: "#f39c12", border: "1px solid rgba(243,156,18,0.35)" }}>
          EXTENSOR
        </div>
        {nat_habilitado && (
          <div className="nt-badge" style={{ background: "rgba(255,51,102,0.15)", color: "#ff3366", border: "1px solid rgba(255,51,102,0.35)" }}>
            Doble NAT 🛡️
          </div>
        )}
        <div className="nt-badge" style={{ background: "rgba(255,255,255,0.05)", color: "#7a8ba8" }}>
          {deviceCount} dispositivos
        </div>
      </div>
    </div>
  );
}

/* ─── CARD: INVISIBLE ───────────────────────────────────────── */
function InvisibleCard() {
  return (
    <div className="nt-card nt-card--invisible" style={{ opacity: 0.6, border: "1px solid rgba(255,255,255,0.1)", background: "rgba(30,41,59,0.5)" }}>
      <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%)" }} />
      <div className="nt-card-icon" style={{ filter: "grayscale(100%)", opacity: 0.7 }}>👻</div>
      <div className="nt-card-label" style={{ color: "#7a8ba8", fontStyle: "italic" }}>Hop Invisible</div>
      <div className="nt-badge" style={{ background: "rgba(255,255,255,0.05)", color: "#7a8ba8", border: "1px solid rgba(255,255,255,0.1)" }}>
        ICMP BLOQUEADO
      </div>
    </div>
  );
}

function InvisibleGroupCard({ count }) {
  const [expanded, setExpanded] = useState(false);
  
  if (expanded) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {Array.from({ length: count }).map((_, i) => (
          <InvisibleCard key={i} />
        ))}
        <button onClick={(e) => { e.stopPropagation(); setExpanded(false); }} className="nt-badge" style={{ background: "rgba(255,255,255,0.1)", color: "#fff", cursor: "pointer", border: "none", margin: "0 auto" }}>
          ▲ Colapsar
        </button>
      </div>
    );
  }

  return (
    <div className="nt-card nt-card--invisible-group" onClick={() => setExpanded(true)} style={{ opacity: 0.8, border: "1px dashed rgba(255,255,255,0.3)", background: "rgba(30,41,59,0.8)", cursor: "pointer" }}>
      <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%)" }} />
      <div className="nt-card-icon" style={{ filter: "grayscale(100%)", opacity: 0.9 }}>🔗</div>
      <div className="nt-card-label" style={{ color: "#cbd5e1", fontWeight: "bold" }}>{count} Hops Invisibles</div>
      <div className="nt-badge" style={{ background: "rgba(255,255,255,0.1)", color: "#cbd5e1", border: "1px solid rgba(255,255,255,0.2)" }}>
        HACER CLIC PARA EXPANDIR
      </div>
    </div>
  );
}

/* ─── CARD: DISPOSITIVO ─────────────────────────────────────── */
function DeviceCard({ device, onVulnClick, routerIp }) {
  const [open, setOpen] = useState(false);
  const color = getScoreColor(device.max_score);
  const hasPorts = device.puertos_abiertos?.length > 0;
  const hasVulns = device.total_vulnerabilidades > 0;

  return (
    <div className="nt-device-wrapper">
      <div
        className="nt-card nt-card--device"
        style={{ "--risk-color": color, cursor: hasPorts ? "pointer" : "default" }}
        onClick={(e) => {
          if (hasPorts) setOpen(!open);
        }}
      >
        <div className="nt-card-glow" style={{ background: `radial-gradient(circle, ${color}22 0%, transparent 70%)` }} />
        <div className="nt-card-icon">{getDeviceIcon(device, routerIp)}</div>
        <div className="nt-card-ip">{device.ip}</div>
        {device.hostname && device.hostname !== "Caché Local ARP" && (
          <div className="nt-card-hostname">{device.hostname}</div>
        )}
        {device.fabricante && device.fabricante !== "Desconocido" && (
          <div className="nt-card-fab">{device.fabricante}</div>
        )}
        <div style={{ display: "flex", gap: 5, justifyContent: "center", flexWrap: "wrap" }}>
          {device.max_score > 0 ? (
            <div className="nt-badge" style={{ background: `${color}22`, color, border: `1px solid ${color}55`, fontWeight: 800 }}>
              {device.max_score.toFixed(1)} {getRiskLabel(device.max_score)}
            </div>
          ) : (
            <div className="nt-badge" style={{ background: "rgba(0,255,136,0.1)", color: "#00ff88", border: "1px solid rgba(0,255,136,0.25)" }}>
              ✓ SEGURO
            </div>
          )}
          {hasVulns && (
            <div 
              className="nt-badge" 
              style={{ background: "rgba(255,51,102,0.1)", color: "#ff3366", border: "1px solid rgba(255,51,102,0.25)", cursor: "pointer" }}
              onClick={(e) => {
                e.stopPropagation();
                if (onVulnClick) onVulnClick(device.ip);
              }}
              title="Ver detalles en Vista Lista"
            >
              {device.total_vulnerabilidades} CVE ↗
            </div>
          )}
          {device.es_nuevo && (
            <div className="nt-badge" style={{ background: "rgba(255,51,102,0.15)", color: "#ff3366", border: "1px solid #ff336650" }}>
              🚨 NUEVO
            </div>
          )}
          {hasPorts && (
            <div className="nt-badge" style={{ background: "rgba(255,255,255,0.05)", color: "#7a8ba8" }}>
              {device.puertos_abiertos.length} puertos {open ? "▾" : "▸"}
            </div>
          )}
        </div>
      </div>

      {/* Puertos expandibles */}
      {open && hasPorts && (
        <div className="nt-ports-popup">
          {device.puertos_abiertos.map((p, i) => {
            const pHasVulns = p.vulnerabilidades?.length > 0;
            const pColor = pHasVulns ? getScoreColor(Math.max(...p.vulnerabilidades.map(v => v.score || 0))) : "#4a5568";
            return (
              <div 
                key={i} 
                className="nt-port-row" 
                style={{ "--pc": pColor, cursor: pHasVulns ? "pointer" : "default" }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (pHasVulns && onVulnClick) onVulnClick(device.ip);
                }}
                title={pHasVulns ? "Ver detalles en Vista Lista" : ""}
              >
                <span className="nt-port-dot" style={{ background: pColor }} />
                <span className="nt-port-num">:{p.puerto}</span>
                <span className="nt-port-svc">{p.servicio}</span>
                {p.version && <span className="nt-port-ver">{p.version}</span>}
                {pHasVulns && (
                  <span style={{ marginLeft: "auto", color: pColor, fontSize: 11, fontWeight: 700 }}>
                    ⚠ {p.vulnerabilidades.length} CVE ↗
                  </span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ─── RAMA DEL ÁRBOL (nodo + hijos) ─────────────────────────── */
function OrgBranch({ card, children }) {
  return (
    <li className="nt-branch">
      {card}
      {children && (
        <ul className="nt-children">
          {children}
        </ul>
      )}
    </li>
  );
}

/* ─── COMPONENTE PRINCIPAL ──────────────────────────────────── */
export default function NetworkTree({ devices, topology, onVulnClick }) {
  const tree = useMemo(() => buildTree(devices, topology), [devices, topology]);
  const viewportRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [showWarnings, setShowWarnings] = useState(false);
  const dragging = useRef(false);
  const lastPos = useRef({ x: 0, y: 0 });

  /* Pan con drag */
  const onMouseDown = useCallback((e) => {
    if (e.target.closest(".nt-card") || e.target.closest(".nt-ports-popup")) return;
    dragging.current = true;
    lastPos.current = { x: e.clientX, y: e.clientY };
    e.currentTarget.style.cursor = "grabbing";
  }, []);
  const onMouseMove = useCallback((e) => {
    if (!dragging.current) return;
    const vp = viewportRef.current;
    vp.scrollLeft -= e.clientX - lastPos.current.x;
    vp.scrollTop  -= e.clientY - lastPos.current.y;
    lastPos.current = { x: e.clientX, y: e.clientY };
  }, []);
  const onMouseUp = useCallback((e) => {
    dragging.current = false;
    e.currentTarget.style.cursor = "grab";
  }, []);

  /* Zoom con rueda */
  const onWheel = useCallback((e) => {
    e.preventDefault();
    setZoom(z => Math.min(Math.max(z * (e.deltaY > 0 ? 0.92 : 1.08), 0.3), 2.5));
  }, []);

  if (!tree) {
    return (
      <div className="nt-empty">
        <div style={{ fontSize: 48 }}>🌐</div>
        <p>No hay datos para construir el árbol.</p>
      </div>
    );
  }

  const { isp, main, extensors } = tree;
  const hasExtensors = extensors && extensors.length > 0;
  const warnings = topology?.advertencias || [];

  return (
    <div className="nt-root">
      
      {/* Alertas Toggle */}
      {warnings.length > 0 && (
        <div style={{ position: "absolute", top: 60, left: 20, zIndex: 10 }}>
          <button 
            onClick={() => setShowWarnings(!showWarnings)}
            style={{ background: "#ff8c00", color: "#111827", padding: "6px 12px", border: "none", borderRadius: 4, fontWeight: "bold", cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontSize: 13, boxShadow: "0 4px 12px rgba(255, 140, 0, 0.3)" }}
          >
            ⚠️ {warnings.length} Alertas de Topología {showWarnings ? "▲" : "▼"}
          </button>
          {showWarnings && (
            <div style={{ background: "rgba(17, 24, 39, 0.9)", border: "1px solid rgba(255, 140, 0, 0.5)", borderRadius: 8, padding: 16, marginTop: 8, maxWidth: 350, backdropFilter: "blur(8px)", boxShadow: "0 8px 32px rgba(0,0,0,0.5)" }}>
              <h4 style={{ margin: "0 0 10px 0", color: "#ff8c00", fontSize: 14 }}>Advertencias de Escaneo</h4>
              <ul style={{ margin: 0, paddingLeft: 20, color: "#e2e8f0", fontSize: 13, display: "flex", flexDirection: "column", gap: 8 }}>
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Leyenda */}
      <div className="nt-legend">
        {[
          { color: "#00d4ff", label: "Internet" },
          { color: "#7b9fff", label: "Gateway" },
          { color: "#f39c12", label: "Extensor / AP" },
          { color: "#00ff88", label: "Seguro" },
          { color: "#ffd000", label: "Riesgo Medio" },
          { color: "#ff3366", label: "Riesgo Crítico" },
        ].map(({ color, label }) => (
          <span key={label} className="nt-legend-item">
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: color, display: "inline-block", flexShrink: 0 }} />
            {label}
          </span>
        ))}
        <span className="nt-legend-item" style={{ marginLeft: "auto", color: "#4a5568", fontSize: 11 }}>
          🖱 Arrastrar para mover · Rueda para zoom
        </span>
      </div>

      {/* Viewport pan/zoom */}
      <div
        className="nt-viewport"
        ref={viewportRef}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onWheel={onWheel}
        style={{ cursor: "grab" }}
      >
        <div className="nt-canvas" style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}>
          <ul className="nt-children nt-children--root">

            {/* INTERNET → GATEWAY */}
            <OrgBranch
              card={
                <div className="nt-card nt-card--internet">
                  <div className="nt-card-glow" style={{ background: "radial-gradient(circle, rgba(0,212,255,0.3) 0%, transparent 70%)" }} />
                  <div className="nt-card-icon">🌐</div>
                  <div className="nt-card-label">Internet</div>
                  {isp && <div className="nt-card-ip">{isp.ip}</div>}
                  <div className="nt-badge" style={{ background: "rgba(0,212,255,0.15)", color: "#00d4ff", border: "1px solid rgba(0,212,255,0.3)" }}>
                    ISP PÚBLICO
                  </div>
                </div>
              }
            >
              <OrgBranch
                card={
                  <GatewayCard
                    ip={main.gateway?.ip || `${main.prefix}.1`}
                    hostname={main.gateway?.hostname}
                    fabricante={main.gateway?.fabricante || main.gateway?.mac}
                  />
                }
              >
                {/* Dispositivos directos en la red principal (Agrupados de a 5) */}
                {chunkArray(main.devices, 5).map((chunk, i) => (
                  <OrgBranch key={`main-chunk-${i}`} card={
                    <div style={{ display: 'flex', flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', gap: '16px', maxWidth: '600px' }}>
                      {chunk.map(d => <DeviceCard key={d.ip} device={d} onVulnClick={onVulnClick} routerIp={topology?.router_principal_ip} />)}
                    </div>
                  } />
                ))}

                {/* Extensores con sus dispositivos */}
                {hasExtensors && extensors.map((ext, i) => (
                  <OrgBranch
                    key={ext.prefix}
                    card={
                      ext.isGroup ? (
                        <InvisibleGroupCard count={ext.count} />
                      ) : ext.gateway?.tipo === "invisible" ? (
                        <InvisibleCard />
                      ) : (
                        <ExtensorCard
                          ip={ext.gateway?.ip || `${ext.prefix}.1`}
                          hostname={ext.gateway?.hostname}
                          fabricante={ext.gateway?.fabricante || ext.gateway?.mac}
                          deviceCount={ext.devices.length}
                          nat_habilitado={ext.gateway?.nat_habilitado}
                        />
                      )
                    }
                  >
                    {/* Dispositivos del extensor (Agrupados de a 5) */}
                    {chunkArray(ext.devices, 5).map((chunk, j) => (
                      <OrgBranch key={`ext-chunk-${j}`} card={
                        <div style={{ display: 'flex', flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', gap: '16px', maxWidth: '600px' }}>
                          {chunk.map(d => <DeviceCard key={d.ip} device={d} onVulnClick={onVulnClick} routerIp={topology?.router_principal_ip} />)}
                        </div>
                      } />
                    ))}
                  </OrgBranch>
                ))}
              </OrgBranch>
            </OrgBranch>

          </ul>
        </div>
      </div>

      {/* Controles de zoom */}
      <div className="nt-controls">
        <button className="nt-ctrl-btn" onClick={() => setZoom(z => Math.min(z * 1.15, 2.5))} title="Zoom +">＋</button>
        <span className="nt-zoom-label">{Math.round(zoom * 100)}%</span>
        <button className="nt-ctrl-btn" onClick={() => setZoom(z => Math.max(z * 0.85, 0.3))} title="Zoom −">－</button>
        <button className="nt-ctrl-btn" onClick={() => setZoom(1)} title="Restablecer">⊡</button>
        <button 
          className="nt-ctrl-btn" 
          onClick={() => {
            const root = document.querySelector('.nt-root');
            if (!document.fullscreenElement) {
              root.requestFullscreen().catch(err => console.log(err));
            } else {
              document.exitFullscreen();
            }
          }} 
          title="Pantalla Completa"
          style={{ marginLeft: 8 }}
        >
          ⛶
        </button>
      </div>
    </div>
  );
}
