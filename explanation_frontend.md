# Frontend Overview – SecScan

## Project Layout
```
C:\Users\Martin\Desktop\escaner\frontend\
│   vite.config.js          # Configuración de Vite
│   index.html              # Entrada HTML
│   package.json            # Dependencias y scripts npm
│
└───src
    │   main.jsx          # Punto de entrada React – monta <App/>
    │   App.jsx           # Contenedor principal, gestiona rutas y vistas
    │   index.css         # Estilos globales (tema, tipografía, layout)
    │
    ├───components          # Componentes reutilizables
    │   │   NetworkTree.jsx        # árbol topológico interactivo
    │   │   DeviceCard.jsx         # tarjeta de dispositivo individual
    │   │   GatewayCard.jsx        # tarjeta de router principal
    │   │   ExtensorCard.jsx       # tarjeta de extensores/APs
    │   │   InvisibleCard.jsx       # hops invisibles (ICMP bloqueado)
    │   │   InvisibleGroupCard.jsx # agrupación de hops invisibles
    │   │   ...
    │
    └───pages               # Vistas de la aplicación (react‑router)
        │   Home.jsx               # pantalla de bienvenida
        │   ScanHistoryPage.jsx    # lista de escaneos realizados
        │   ScanDetailsPage.jsx    # página de resultados (lista / árbol / consola)
        │   Settings.jsx           # configuración del usuario
```

## Core Concepts

### 1. **Routing (react‑router)**
- `main.jsx` envuelve `<BrowserRouter>` y renderiza `<App />`.
- `App.jsx` define las rutas principales:
  ```tsx
  <Routes>
    <Route path="/" element={<Home />} />
    <Route path="/history" element={<ScanHistoryPage />} />
    <Route path="/history/:scanId" element={<ScanDetailsPage />} />
  </Routes>
  ```
- El **estado de la vista** (`lista`, `arbol`, `consola`) se pasa vía `location.state` y se almacena en `useState` dentro de `ScanDetailsPage`.

### 2. **State Management (React hooks)**
| Hook | Uso | Comentario |
|------|-----|------------|
|`useState`|Control de carga (`loading`), datos (`devices`, `vulns`, `topology`), vista actual (`vista`), logs (`scanLogs`).| Simple y local; suficiente porque cada página gestiona su propio estado.
|`useEffect`|Polling de Firestore cada 5 s mientras el escaneo está en proceso.| Inicia el `setInterval` cuando `isProcessing` es `true` y lo limpia al desmontar.
|`useCallback`|Función `loadData` que llama a los endpoints `getScanDevices`, `getScanDetails` y actualiza el estado.| Evita re‑creación innecesaria en el `useEffect`.
|`useMemo`|Construye el árbol topológico a partir de `devices` y `topology` usando `buildTree`.| Mejora rendimiento porque la transformación sólo ocurre cuando cambian los arrays.

### 3. **Data Flow**
1. **Inicio de escáner** → `handleFullScan` (en `Home.jsx`).
2. Llama a `POST /api/scan/start` → FastAPI crea `scanId` y lanza tarea en background.
3. FastAPI escribe logs en **Firestore** bajo `scans/{scanId}/logs`.
4. `ScanDetailsPage` usa `loadData` para obtener:
   - `devices` (`GET /api/v1/scans/:id/devices`)
   - `details` (`GET /api/v1/scans/:id/details`) que incluye `topology` y `logs`.
5. Los datos se propagan a los componentes:
   - **NetworkTree** → `devices` + `topology` → renderiza los nodos e interconexiones.
   - **Consola** → `scanLogs` → muestra cada línea con decoración CSS.
   - **Lista** → tabla de dispositivos y vulnerabilidades.

## Componentes Principales

### `App.jsx`
- Gestiona la navegación global.
- Define el **botón de toggle** que permite cambiar entre `lista`, `arbol` y `consola`.
- Incluye la lógica de redirección al terminar el escaneo (ahora a vista `arbol`).
- Mantiene el estado `scanLogs` que alimenta la consola.

### `NetworkTree.jsx`
- **Funciones auxiliares** (`isPrivateIP`, `getSubnetPrefix`, `buildTree`).
- Construye la estructura jerárquica: `Internet → Router → Extensores → Dispositivos`.
- Cada nodo es una **card** con colores temáticos y badge de riesgo.
- Soporta **zoom** (mouse wheel) y **drag‑pan** para explorar árboles grandes.
- Botones de control (`+`, `-`, `reset`, fullscreen) están en `.nt-controls`.

### `DeviceCard.jsx`
- Muestra IP, hostname, fabricante, puertos y vulnerabilidades.
- Si tiene puertos, permite expandir una *popup* con los detalles.
- Usa `getDeviceIcon` para asignar un emoji representativo (router, smartphone, TV, etc.).

### `GatewayCard.jsx` / `ExtensorCard.jsx` / `InvisibleCard.jsx`
- Personalizan la apariencia según tipo de nodo.
- `GatewayCard` muestra *Router Principal*.
- `ExtensorCard` muestra APs o extensores, con badge de NAT si está habilitado.
- `InvisibleCard` indica hops que no respondieron a ICMP.

### `Consola` (en `App.jsx`)
```tsx
{scanLogs.map((log,i)=> (
  <div key={i} className="terminal-line">
    <span className="terminal-prompt">$</span> {log}
  </div>
))}
```
- Cada línea tiene la clase `.terminal-line`.
- La última línea muestra una flecha `▶` animada (`animation: blink`).
- Estilos: `index.css` → `.terminal-line`, `.terminal-prompt`.

## Styling (CSS) Highlights (`index.css`)
- **Bento Grid**: `.bento-grid` → layout de tarjetas responsivo (3 col). 
- **Cards**: `.bento-card` con glow radial y hover transform.
- **Tree**: clases `nt-*` (root, viewport, canvas, branch, card) que usan **gradientes púrpura** y **shadow** para resaltar la jerarquía.
- **Consola**: `.terminal-line`, `.terminal-prompt`, `.terminal-line:last-child::after {content: ' ▶';}`.
- **Responsive**: media queries para reducir a 2 columnas en dispositivos móviles.

## How the Frontend Handles Data
1. **Polling** – `setInterval` cada 5 s mientras `isProcessing` es true. Llama a `loadData` que refresca `devices`, `vulns`, `topology` y `scanLogs`.
2. **Error handling** – `try/catch` dentro de `loadData`; en caso de error muestra `console.error` y mantiene la UI en estado anterior.
3. **User interactions** –
   - Click en nodo de dispositivo → `setTimeout(() => scrollToVuln(ip), 150)` para enfocar vulnerabilidad en la vista lista.
   - Click en botones de zoom/pan para mover y escalar el árbol.
   - Cambiar vista con `setVista('lista'|'arbol'|'consola')`.

## Extensibility – Adding New Features
| Feature | Files to Touch | What to Add |
|---------|----------------|------------|
| Nueva vista (ej. *Heatmap*) | `src/pages/Heatmap.jsx`, `src/App.jsx` (botón toggle) | Component que consuma `scanLogs` o `devices` y dibuje mapa de calor. |
| Soporte para **Scapy** (packet‑crafting) | `backend/core/scapy_scanner.py`, `backend/api/v1/endpoints/scans.py` | Función que use `scapy.sendrecv` para pruebas de ARP/ICMP; registra logs vía `_log`. |
| Mejora del polling → **WebSocket** | `backend/api/v1/websocket.py`, `src/hooks/useWebSocket.js` | Suscripción a Firestore o a FastAPI websockets para recibir logs en tiempo real. |
| Tema oscuro / claro | `src/index.css` (variables CSS), `src/components/ThemeSwitcher.jsx` | Cambiar valores de `--bg-…` y persistir en `localStorage`. |

## Simple Explanations of Hard Concepts
- **Scapy**: Es una librería Python que permite **crear, enviar y capturar paquetes** de red de forma programática (ej. enviar un ping ARP y leer la respuesta). En nuestro proyecto, podríamos usarla para validar que un host está activo antes de lanzar Nmap. Se usa así:
  ```python
  from scapy.all import sr1, IP, ICMP
  resp = sr1(IP(dst='192.168.1.10')/ICMP(), timeout=2)
  if resp:
      print('Host alive')
  ```
  Cada llamada a `sr1` genera un log vía `_log` para que la consola lo muestre.

- **Scan ID**: Cada escaneo recibe un UUID (`scan_id = uuid4()`). Sirve como **clave única** para:
  1. Guardar logs en Firestore bajo `scans/{scan_id}/logs`.
  2. Acceder a los resultados (`/api/v1/scans/:id/devices`).
  3. Navegar en la UI (`/history/<scan_id>`).  De esta forma, varios usuarios pueden ejecutar escaneos simultáneos sin mezclar datos.

- **Thread‑local logging**: `threading.local()` crea un espacio de memoria **único por hilo**. Cuando FastAPI lanza la tarea de escaneo, asigna `thread_local.log_cb = lambda msg: db.append_log(scan_id, msg)`. Cada hilo (escaneo) escribe sus logs en su propio documento, evitando colisiones.

## Summary
- El **frontend** está construido sobre React + Vite, con una arquitectura de componentes clara y un estado manejado mediante hooks.
- La **navegación** usa react‑router, y la **vista actual** se controla con un simple toggle.
- Los **datos** llegan desde FastAPI mediante polling a Firestore y se renderizan en tres vistas distintas: Lista, Árbol y Consola.
- El **código** está organizado para que sea fácil añadir nuevas funcionalidades (Scapy, WebSocket, temas, nuevas vistas).
- Conceptos complejos (Scapy, Scan ID, logging thread‑local) están explicados en lenguaje sencillo arriba.

---
**Archivo creado**: `C:/Users/Martin/Desktop/escaner/explanation_frontend.md`

Puedes abrirlo para revisar esta documentación detallada. Si deseas agregar o modificar alguna sección, avísame. ¡Éxitos con la presentación!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
