import os
import firebase_admin
from firebase_admin import credentials, firestore

class FirebaseDB:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FirebaseDB, cls).__new__(cls)
            
            ruta_actual = os.path.dirname(os.path.abspath(__file__))
            ruta_llave = os.path.join(ruta_actual, '..', 'firebase_admin.json')
            
            try:
                if not firebase_admin._apps:
                    cred = credentials.Certificate(ruta_llave)
                    firebase_admin.initialize_app(cred)
                cls._instance.db = firestore.client()
                print("[OK] Conexion a Firebase Firestore establecida.")
            except Exception as e:
                print(f"[ERROR] Error al iniciar Firebase: {str(e)}")
                raise e
        return cls._instance

    def get_db(self):
        return self.db
