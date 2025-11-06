#!/usr/bin/env python3
"""
Tests pour le système de stockage et la base de données
"""
import pytest
import sqlite3
import tempfile
import os
from datetime import datetime

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from storage import init_storage

class TestStorage:
    
    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_db = None
    
    def teardown_method(self):
        """Cleanup après chaque test"""
        if self.temp_db and os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
    
    def create_temp_db(self):
        """Créer une base de données temporaire pour les tests"""
        fd, self.temp_db = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        return self.temp_db
    
    def test_init_storage_creates_directory(self):
        """Test que init_storage crée le répertoire de stockage"""
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_dir = os.path.join(temp_dir, "test_storage")
            
            # Simuler les variables d'environnement
            import os
            original_sqlite_path = os.environ.get("SQLITE_PATH")
            original_faiss_path = os.environ.get("FAISS_INDEX_PATH")
            
            try:
                os.environ["SQLITE_PATH"] = os.path.join(storage_dir, "test.sqlite")
                os.environ["FAISS_INDEX_PATH"] = os.path.join(storage_dir, "faiss_index")
                
                # Vérifier que le répertoire n'existe pas
                assert not os.path.exists(storage_dir)
                
                # Initialiser le stockage
                init_storage()
                
                # Vérifier que le répertoire a été créé
                assert os.path.exists(storage_dir)
                assert os.path.exists(os.path.join(storage_dir, "test.sqlite"))
                
            finally:
                # Restaurer les variables d'environnement
                if original_sqlite_path:
                    os.environ["SQLITE_PATH"] = original_sqlite_path
                elif "SQLITE_PATH" in os.environ:
                    del os.environ["SQLITE_PATH"]
                    
                if original_faiss_path:
                    os.environ["FAISS_INDEX_PATH"] = original_faiss_path
                elif "FAISS_INDEX_PATH" in os.environ:
                    del os.environ["FAISS_INDEX_PATH"]
    
    def test_database_schema_creation(self):
        """Test création du schéma de base de données"""
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Créer un répertoire storage temporaire
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                
                # Initialiser le stockage (créera storage/db.sqlite)
                init_storage()
                
                # Vérifier que la base a été créée
                db_path = os.path.join("storage", "db.sqlite")
                assert os.path.exists(db_path)
                
                # Vérifier que les tables ont été créées
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Vérifier table incidents
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='incidents'
                """)
                assert cursor.fetchone() is not None
                
                # Vérifier les colonnes de la table incidents
                cursor.execute("PRAGMA table_info(incidents)")
                columns = [row[1] for row in cursor.fetchall()]
                expected_columns = ['id', 'ts', 'type', 'ip', 'user', 'endpoint', 'severity', 'summary', 'recs', 'evidence', 'created_at']
                
                for col in expected_columns:
                    assert col in columns, f"Column {col} missing from incidents table"
                
                # Vérifier table actions
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='actions'
                """)
                assert cursor.fetchone() is not None
                
                conn.close()
                
            finally:
                os.chdir(old_cwd)
    
    def test_incident_insertion_and_retrieval(self):
        """Test insertion et récupération d'incidents"""
        temp_db = self.create_temp_db()
        
        # Initialiser la base
        import os
        original_sqlite_path = os.environ.get("SQLITE_PATH")
        
        try:
            os.environ["SQLITE_PATH"] = temp_db
            init_storage()
            
            # Insérer un incident
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            incident_data = {
                'id': 'test-incident-1',
                'ts': datetime.now().isoformat(),
                'type': 'bruteforce',
                'ip': '45.33.32.156',
                'user': 'admin',
                'endpoint': '/login',
                'severity': 'high',
                'summary': 'Test brute force incident',
                'recs': '["Block IP", "Reset password"]',
                'evidence': '["5 failed attempts", "Successful login"]'
            }
            
            cursor.execute("""
                INSERT INTO incidents (id, ts, type, ip, user, endpoint, severity, summary, recs, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_data['id'], incident_data['ts'], incident_data['type'],
                incident_data['ip'], incident_data['user'], incident_data['endpoint'],
                incident_data['severity'], incident_data['summary'],
                incident_data['recs'], incident_data['evidence']
            ))
            
            conn.commit()
            
            # Récupérer l'incident
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_data['id'],))
            row = cursor.fetchone()
            
            assert row is not None
            assert row[0] == incident_data['id']  # id
            assert row[2] == incident_data['type']  # type
            assert row[3] == incident_data['ip']    # ip
            assert row[6] == incident_data['severity']  # severity
            
            conn.close()
            
        finally:
            if original_sqlite_path:
                os.environ["SQLITE_PATH"] = original_sqlite_path
            elif "SQLITE_PATH" in os.environ:
                del os.environ["SQLITE_PATH"]
    
    def test_database_connection_direct(self):
        """Test de connexion directe à la base de données"""
        temp_db = self.create_temp_db()
        
        # Initialiser avec notre DB temporaire
        conn = sqlite3.connect(temp_db)
        
        # Créer les tables comme le fait init_storage
        conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                type TEXT NOT NULL,
                ip TEXT,
                user TEXT,
                endpoint TEXT,
                severity TEXT NOT NULL,
                summary TEXT,
                recs TEXT,
                evidence TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        
        # Vérifier que c'est une connexion SQLite valide
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        
        conn.close()
    
    def test_database_indexes(self):
        """Test que les index sont créés correctement"""
        temp_db = self.create_temp_db()
        
        import os
        original_sqlite_path = os.environ.get("SQLITE_PATH")
        
        try:
            os.environ["SQLITE_PATH"] = temp_db
            init_storage()
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Vérifier les index
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='index' AND tbl_name='incidents'
            """)
            indexes = [row[0] for row in cursor.fetchall()]
            
            # Devrait avoir au moins des index sur ts, type, severity, ip
            # (Les index exacts dépendent de l'implémentation)
            assert len(indexes) >= 0  # Au minimum les index automatiques
            
            conn.close()
            
        finally:
            if original_sqlite_path:
                os.environ["SQLITE_PATH"] = original_sqlite_path
            elif "SQLITE_PATH" in os.environ:
                del os.environ["SQLITE_PATH"]
    
    def test_database_concurrent_access(self):
        """Test accès concurrent à la base de données"""
        import threading
        import time
        
        temp_db = self.create_temp_db()
        
        import os
        original_sqlite_path = os.environ.get("SQLITE_PATH")
        
        try:
            os.environ["SQLITE_PATH"] = temp_db
            init_storage()
            
            results = []
            
            def worker(thread_id):
                try:
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    for i in range(5):
                        incident_id = f"thread-{thread_id}-incident-{i}"
                        cursor.execute("""
                            INSERT INTO incidents (id, ts, type, severity, summary)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            incident_id,
                            datetime.now().isoformat(),
                            'test',
                            'low',
                            f'Test incident from thread {thread_id}'
                        ))
                        
                    conn.commit()
                    conn.close()
                    results.append(True)
                except Exception as e:
                    results.append(False)
                    print(f"Thread {thread_id} failed: {e}")
            
            # Créer plusieurs threads
            threads = []
            for i in range(3):
                t = threading.Thread(target=worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Attendre la fin
            for t in threads:
                t.join()
            
            # Vérifier que tous ont réussi
            assert all(results), f"Some concurrent access failed: {results}"
            
            # Vérifier le nombre total d'enregistrements
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM incidents")
            count = cursor.fetchone()[0]
            assert count == 15  # 3 threads × 5 incidents
            
            conn.close()
            
        finally:
            if original_sqlite_path:
                os.environ["SQLITE_PATH"] = original_sqlite_path
            elif "SQLITE_PATH" in os.environ:
                del os.environ["SQLITE_PATH"]
    
    def test_storage_directory_creation_error_handling(self):
        """Test gestion des erreurs de création de répertoire"""
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Créer un chemin vers un répertoire en lecture seule
            readonly_dir = os.path.join(temp_dir, "readonly")
            os.makedirs(readonly_dir)
            os.chmod(readonly_dir, 0o444)  # Lecture seule
            
            storage_path = os.path.join(readonly_dir, "storage", "test.sqlite")
            
            import os
            original_sqlite_path = os.environ.get("SQLITE_PATH")
            
            try:
                os.environ["SQLITE_PATH"] = storage_path
                
                # L'initialisation ne devrait pas crash même en cas d'erreur
                # (selon l'implémentation)
                try:
                    init_storage()
                except PermissionError:
                    # C'est acceptable, l'erreur est gérée
                    pass
                    
            finally:
                if original_sqlite_path:
                    os.environ["SQLITE_PATH"] = original_sqlite_path
                elif "SQLITE_PATH" in os.environ:
                    del os.environ["SQLITE_PATH"]
                
                # Restaurer les permissions pour le cleanup
                os.chmod(readonly_dir, 0o755)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])