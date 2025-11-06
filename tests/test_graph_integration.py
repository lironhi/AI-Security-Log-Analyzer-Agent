#!/usr/bin/env python3
"""
Integration tests for LangGraph graph and complete workflow
"""
import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestGraphIntegration:
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_files = []
    
    def teardown_method(self):
        """Cleanup after each test"""
        for file_path in self.temp_files:
            if os.path.exists(file_path):
                os.unlink(file_path)
    
    def create_test_log_file(self, log_type="apache"):
        """Create a temporary log file for tests"""
        if log_type == "apache":
            content = '''192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"
45.33.32.156 - - [01/Jan/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"
45.33.32.156 - - [01/Jan/2024:10:05:30 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"
45.33.32.156 - - [01/Jan/2024:10:06:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"
45.33.32.156 - - [01/Jan/2024:10:06:30 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"
45.33.32.156 - - [01/Jan/2024:10:07:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"
45.33.32.156 - admin [01/Jan/2024:10:08:00 +0000] "POST /login HTTP/1.1" 200 1024 "-" "AttackBot/1.0"
192.168.1.50 - - [01/Jan/2024:10:10:00 +0000] "GET /api/process HTTP/1.1" 500 0 "-" "Mozilla/5.0"
192.168.1.51 - - [01/Jan/2024:10:10:30 +0000] "GET /api/process HTTP/1.1" 500 0 "-" "Mozilla/5.0"
192.168.1.52 - - [01/Jan/2024:10:11:00 +0000] "GET /api/process HTTP/1.1" 500 0 "-" "Mozilla/5.0"'''
        elif log_type == "jsonl":
            content = '''{"ts": "2024-01-01T10:00:00Z", "ip": "192.168.1.100", "endpoint": "/dashboard", "status": 200, "method": "GET"}
{"ts": "2024-01-01T10:05:00Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"}
{"ts": "2024-01-01T10:05:30Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"}
{"ts": "2024-01-01T10:06:00Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"}
{"ts": "2024-01-01T10:08:00Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 200, "method": "POST", "user": "admin"}'''
        
        suffix = ".log" if log_type == "apache" else ".jsonl"
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        self.temp_files.append(temp_path)
        return temp_path
    
    @pytest.mark.asyncio
    async def test_complete_workflow_apache_logs(self):
        """Test complete workflow with Apache logs"""
        from agents.graph import security_graph
        
        log_file = self.create_test_log_file("apache")
        
        # Exécuter le workflow complet
        result = await security_graph.process_logs(log_file, window_hours=24)
        
        # Vérifier la structure du résultat
        assert isinstance(result, dict)
        assert "incidents" in result
        assert "metadata" in result
        assert "summary" in result
        
        # Vérifier les métadonnées
        metadata = result["metadata"]
        assert "status" in metadata
        assert metadata["status"] == "success" or "ingested_count" in metadata
        
        # Vérifier les incidents (peut être vide en mode mock)
        incidents = result["incidents"]
        assert isinstance(incidents, list)
        
        # En mode réel, devrait détecter une brute force
        # En mode mock, peut être vide selon la configuration
        if len(incidents) > 0:
            incident = incidents[0]
            assert "id" in incident
            assert "type" in incident
            assert "severity" in incident
            assert "summary" in incident
    
    @pytest.mark.asyncio
    async def test_complete_workflow_jsonl_logs(self):
        """Test complete workflow with JSONL logs"""
        from agents.graph import security_graph
        
        log_file = self.create_test_log_file("jsonl")
        
        result = await security_graph.process_logs(log_file, window_hours=24)
        
        assert isinstance(result, dict)
        assert "incidents" in result
        assert "metadata" in result
        
        # Vérifier qu'aucune erreur ne s'est produite
        if "error" in result.get("metadata", {}):
            pytest.fail(f"Workflow failed: {result['metadata']['error']}")
    
    @pytest.mark.asyncio
    async def test_workflow_with_nonexistent_file(self):
        """Test workflow with non-existent file"""
        from agents.graph import security_graph
        
        result = await security_graph.process_logs("/nonexistent/file.log", window_hours=24)
        
        # Devrait gérer l'erreur gracieusement
        assert isinstance(result, dict)
        assert "incidents" in result
        assert result["incidents"] == []
        
        # Peut contenir une erreur dans les métadonnées
        if "metadata" in result:
            # L'erreur peut être reportée ici
            pass
    
    @pytest.mark.asyncio
    async def test_workflow_state_progression(self):
        """Test state progression in workflow"""
        from agents.graph import SecurityAnalysisGraph
        
        graph = SecurityAnalysisGraph()
        log_file = self.create_test_log_file("apache")
        
        # État initial
        initial_state = {
            "logs": [],
            "chunks": [],
            "incidents": [],
            "investigation_contexts": [],
            "final_incidents": [],
            "metadata": {
                "log_path": log_file,
                "window_hours": 24,
                "started_at": datetime.now().isoformat()
            }
        }
        
        # Test de chaque étape individuellement
        
        # 1. Ingestion
        state_after_ingest = await graph._ingest_logs(initial_state.copy())
        assert "logs" in state_after_ingest
        
        # 2. Chunking
        state_after_chunk = await graph._chunk_and_embed(state_after_ingest.copy())
        assert "chunks" in state_after_chunk
        
        # 3. Détection
        state_after_detection = await graph._detect_anomalies(state_after_chunk.copy())
        assert "incidents" in state_after_detection
        
        # Chaque étape doit maintenir l'état précédent
        assert state_after_detection.get("logs") is not None
        assert state_after_detection.get("chunks") is not None
    
    @pytest.mark.asyncio
    async def test_workflow_error_recovery(self):
        """Test error recovery in workflow"""
        from agents.graph import SecurityAnalysisGraph
        
        graph = SecurityAnalysisGraph()
        
        # État avec erreur simulée
        error_state = {
            "logs": [],
            "chunks": [],
            "incidents": [],
            "investigation_contexts": [],
            "final_incidents": [],
            "metadata": {
                "log_path": None,  # Path invalide
                "window_hours": 24
            }
        }
        
        # Test que l'ingestion gère le path invalide
        result_state = await graph._ingest_logs(error_state)
        
        # Devrait continuer sans crash
        assert "logs" in result_state
        assert isinstance(result_state["logs"], list)
    
    @pytest.mark.asyncio
    async def test_workflow_memory_usage(self):
        """Test de l'utilisation mémoire du workflow"""
        import psutil
        import os
        from agents.graph import security_graph
        
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        # Créer un gros fichier de log
        large_log_content = ""
        for i in range(1000):
            large_log_content += f'192.168.1.{i % 255} - - [01/Jan/2024:10:{i:02d}:00 +0000] "GET /page{i} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(large_log_content)
            large_log_file = f.name
        
        self.temp_files.append(large_log_file)
        
        # Traiter le gros fichier
        result = await security_graph.process_logs(large_log_file, window_hours=24)
        
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = memory_after - memory_before
        
        # Vérifier que l'augmentation mémoire reste raisonnable (< 500MB)
        assert memory_increase < 500, f"Memory usage increased by {memory_increase:.2f}MB"
        
        # Vérifier que le traitement a réussi
        assert isinstance(result, dict)
        assert "incidents" in result
    
    @pytest.mark.asyncio 
    async def test_workflow_parallel_processing(self):
        """Test traitement en parallèle de plusieurs fichiers"""
        import asyncio
        from agents.graph import security_graph
        
        # Créer plusieurs fichiers
        log_files = [
            self.create_test_log_file("apache"),
            self.create_test_log_file("jsonl"),
            self.create_test_log_file("apache")
        ]
        
        # Traiter en parallèle
        tasks = [
            security_graph.process_logs(log_file, window_hours=24)
            for log_file in log_files
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Vérifier que tous ont réussi
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                pytest.fail(f"Parallel processing failed for file {i}: {result}")
            
            assert isinstance(result, dict)
            assert "incidents" in result
            assert "metadata" in result
    
    def test_graph_compilation(self):
        """Test que le graph LangGraph compile correctement"""
        from agents.graph import SecurityAnalysisGraph
        
        # Créer une instance devrait compiler le graph
        graph = SecurityAnalysisGraph()
        
        # Vérifier que le graph est compilé
        assert graph.graph is not None
        assert hasattr(graph.graph, 'invoke') or hasattr(graph.graph, 'ainvoke')
    
    @pytest.mark.asyncio
    async def test_scan_recent_logs(self):
        """Test de scan des logs récents"""
        from agents.graph import security_graph
        
        # Cette fonction devrait retourner une liste même si vide
        incidents = await security_graph.scan_recent_logs(window_hours=24)
        
        assert isinstance(incidents, list)
        # Peut être vide si aucun log récent n'est indexé

if __name__ == "__main__":
    pytest.main([__file__, "-v"])