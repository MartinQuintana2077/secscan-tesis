import React, { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { getScanHistory } from "../services/api";
import { useAuth } from "../context/AuthContext";
import { Clock, Monitor, Shield, FileText, Printer, Calendar, Search } from "lucide-react";

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const { getToken } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Date filter state
  const [dateFilter, setDateFilter] = useState("week"); // 'week', 'all', 'custom'
  const [customDate, setCustomDate] = useState("");

  useEffect(() => {
    async function fetchHistory() {
      try {
        const token = await getToken();
        const data = await getScanHistory(token);
        if (data.status === "ok") {
          // Sort by timestamp descending
          const sorted = (data.scans || []).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
          setScans(sorted);
        }
      } catch (err) {
        console.error("Error cargando historial", err);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, [getToken]);

  const handleScanClick = (scanId) => {
    navigate(`/history/${scanId}`);
  };

  const filteredScans = useMemo(() => {
    if (dateFilter === "all") return scans;
    
    const now = new Date();
    return scans.filter(scan => {
      const scanDate = new Date(scan.timestamp);
      
      if (dateFilter === "week") {
        const diffTime = Math.abs(now - scanDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays <= 7;
      }
      
      if (dateFilter === "custom" && customDate) {
        // match YYYY-MM-DD
        const sDateStr = scanDate.toISOString().split("T")[0];
        return sDateStr === customDate;
      }
      
      return true;
    });
  }, [scans, dateFilter, customDate]);

  return (
    <div className="page-container fade-in">
      <div className="history-top-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <button className="btn btn-back" onClick={() => navigate("/")}>
          ← Volver al Inicio
        </button>
        <button className="btn btn-primary" onClick={() => window.print()} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Printer size={16} className="inline-icon" />
          Imprimir Historial
        </button>
      </div>

      <div className="results-header" style={{ marginBottom: '20px' }}>
        <h1>Auditorías Históricas</h1>
        <p>Historial de análisis y descubrimientos de red.</p>
      </div>

      {/* CONTROLES DE FILTRO */}
      <div className="history-filters" style={{ display: 'flex', gap: '15px', alignItems: 'center', marginBottom: '30px', background: 'var(--bg-surface)', padding: '15px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Calendar size={18} className="inline-icon" color="var(--text-secondary)" />
          <span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-secondary)' }}>Filtrar por Fecha:</span>
        </div>
        
        <select 
          className="bento-select" 
          value={dateFilter} 
          onChange={(e) => setDateFilter(e.target.value)}
          style={{ padding: '8px 12px', borderRadius: '6px', background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', outline: 'none' }}
        >
          <option value="week">Esta semana (Últimos 7 días)</option>
          <option value="all">Todas las fechas</option>
          <option value="custom">Fecha específica...</option>
        </select>

        {dateFilter === "custom" && (
          <input 
            type="date" 
            value={customDate}
            onChange={(e) => setCustomDate(e.target.value)}
            style={{ padding: '7px 12px', borderRadius: '6px', background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', outline: 'none' }}
          />
        )}
      </div>

      {loading ? (
        <div className="scanning-spinner" style={{ margin: "40px auto", width: "40px", height: "40px" }} />
      ) : filteredScans.length > 0 ? (
        <div className="capsule-grid">
          {filteredScans.map((scan, i) => {
            const hasVulns = scan.vulnerabilidades_found > 0;
            return (
              <div 
                key={scan.id} 
                className={`capsule-card slide-up ${hasVulns ? 'danger' : ''}`} 
                style={{ animationDelay: `${i * 0.05}s` }}
                onClick={() => handleScanClick(scan.id)}
              >
                <div className="capsule-header">
                  <div>
                    <div className="capsule-date" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={14} className="inline-icon" /> 
                      {new Date(scan.timestamp).toLocaleString()}
                    </div>
                    <div className="capsule-id">
                      ID: {scan.id.substring(0, 8)} | Org: {scan.ip || 'Auto'}
                    </div>
                  </div>
                  <div className={`capsule-status ${scan.status === 'completed' ? 'completed' : 'processing'}`}>
                    {scan.status === 'completed' ? 'Completado' : scan.status}
                  </div>
                </div>

                <div className="capsule-body">
                  <div className="capsule-stat">
                    <div className="capsule-stat-icon"><Monitor size={18} color="var(--accent-cyan)" /></div>
                    <div className="capsule-stat-value" style={{ color: 'var(--accent-cyan)' }}>
                      {scan.devices_found ?? '?'}
                    </div>
                    <div className="capsule-stat-label">Dispositivos</div>
                  </div>
                  
                  <div className="capsule-stat">
                    <div className="capsule-stat-icon"><Shield size={18} color={hasVulns ? 'var(--accent-red)' : 'var(--accent-green)'} /></div>
                    <div className="capsule-stat-value" style={{ color: hasVulns ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                      {scan.vulnerabilidades_found ?? '?'}
                    </div>
                    <div className="capsule-stat-label">CVEs</div>
                  </div>
                </div>

                <div className="capsule-actions">
                  <button 
                    className="btn-export" 
                    onClick={(e) => { 
                      e.stopPropagation(); 
                      navigate(`/history/${scan.id}`, { state: { defaultView: "lista", autoPrint: true } });
                    }}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <FileText size={14} className="inline-icon" /> Exportar a PDF
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-state-icon" style={{ marginBottom: '16px' }}><Search size={48} color="var(--text-tertiary)" className="inline-icon" /></div>
          <p>No se encontraron escaneos para los filtros seleccionados.</p>
        </div>
      )}
    </div>
  );
}
