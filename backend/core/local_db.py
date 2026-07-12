import os
import sqlite3
import json
import datetime
import threading

class LocalDBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LocalDBManager, cls).__new__(cls)
                cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        # Localización de la base de datos en la carpeta backend/
        ruta_actual = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(ruta_actual, '..', 'secscan_local.db')
        
        # Crear tablas si no existen
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 1. Tabla de Dispositivos (Espejo de Firestore collection "devices")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT,
                user_id TEXT,
                mac TEXT,
                hostname TEXT,
                fabricante TEXT,
                total_vulnerabilidades INTEGER,
                max_score REAL,
                fecha_auditoria TEXT,
                estado TEXT,
                es_nuevo INTEGER,
                primera_conexion TEXT,
                scan_id TEXT,
                PRIMARY KEY (ip, user_id)
            )
        ''')

        # 2. Tabla de Vulnerabilidades (Espejo de Firestore collection "vulnerabilities")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                user_id TEXT,
                descripcion TEXT,
                severidad TEXT,
                score REAL,
                ip TEXT,
                puerto INTEGER,
                servicio TEXT,
                version TEXT,
                fecha_deteccion TEXT
            )
        ''')

        # 3. Tabla de Escaneos (Espejo de Firestore collection "scans")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT,
                user_id TEXT,
                status TEXT,
                devices_found INTEGER,
                total_targets INTEGER,
                vulnerabilidades_found INTEGER,
                timestamp TEXT,
                end_time TEXT,
                topology_json TEXT,
                logs_json TEXT,
                PRIMARY KEY (scan_id, user_id)
            )
        ''')

        # 4. Tabla de Dispositivos por Escaneo Específico (Espejo de subcolección scans/devices)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_devices (
                scan_id TEXT,
                ip TEXT,
                user_id TEXT,
                device_data_json TEXT,
                PRIMARY KEY (scan_id, ip, user_id)
            )
        ''')

        # 5. Tabla de Cola de Sincronización Offline (transacciones pendientes)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS offline_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT,
                user_id TEXT,
                payload_json TEXT,
                timestamp TEXT
            )
        ''')

        # 6. Tabla de Caché de CVEs (NVD API)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                keyword TEXT PRIMARY KEY,
                cves_json TEXT,
                cached_at TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[SQLite] Base de datos local inicializada en: {self.db_path}")

    def get_connection(self):
        """Retorna una conexión a la base de datos SQLite."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    # Métodos genéricos para facilitar lecturas/escrituras rápidas con Locks
    def execute_write(self, query, params=()):
        with self._lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def execute_read(self, query, params=()):
        with self._lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()
