#!/usr/bin/env python3
"""
Integration tests for FastAPI API
"""
import pytest
from fastapi.testclient import TestClient
import json
import tempfile
import os
from datetime import datetime

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock missing dependencies before importing the API
class MockSecurityGraph:
    async def process_logs(self, log_path, window_hours=24):
        return {
            "incidents": [
                {
                    "id": "test-incident-1",
                    "ts": datetime.now().isoformat(),
                    "type": "bruteforce",
                    "severity": "high",
                    "summary": "Test brute force incident",
                    "entities": {"ip": "45.33.32.156"},
                    "evidence": ["Multiple failed login attempts"],
                    "recommendations": ["Block IP address"]
                }
            ],
            "metadata": {
                "ingested_count": 10,
                "indexed_count": 8,
                "status": "success"
            },
            "summary": {
                "severity_breakdown": {"high": 1}
            }
        }
    
    async def scan_recent_logs(self, window_hours=24):
        return []

class MockActions:
    async def block_ip(self, ip, reason="Manual block"):
        return {
            "action_type": "block_ip",
            "target": ip,
            "success": True,
            "message": f"IP {ip} blocked successfully",
            "timestamp": datetime.now().isoformat()
        }
    
    async def unblock_ip(self, ip):
        return {
            "action_type": "unblock_ip",
            "target": ip,
            "success": True,
            "message": f"IP {ip} unblocked successfully",
            "timestamp": datetime.now().isoformat()
        }
    
    async def rate_limit_ip(self, ip, requests_per_minute=10):
        return {
            "action_type": "rate_limit_ip",
            "target": ip,
            "success": True,
            "message": f"Rate limit applied to {ip}",
            "timestamp": datetime.now().isoformat()
        }
    
    async def reset_tokens(self, user):
        return {
            "action_type": "reset_tokens",
            "target": user,
            "success": True,
            "message": f"Tokens reset for user {user}",
            "timestamp": datetime.now().isoformat()
        }
    
    def get_blocked_ips(self):
        return ["45.33.32.156", "192.168.1.100"]
    
    def get_action_history(self):
        return []

# Mock modules before importing the API
sys.modules['agents.graph'] = type(sys)('mock_graph')
sys.modules['agents.graph'].security_graph = MockSecurityGraph()
sys.modules['mcp_tools.actions'] = type(sys)('mock_actions')
sys.modules['mcp_tools.actions'].actions = MockActions()
sys.modules['storage'] = type(sys)('mock_storage')

def mock_init_storage():
    pass

sys.modules['storage'].init_storage = mock_init_storage

# Mock sqlite3 to avoid database errors
import sqlite3
original_connect = sqlite3.connect

def mock_connect(database):
    if database == "storage/db.sqlite":
        # Create in-memory database for tests
        conn = sqlite3.connect(":memory:")
        # Create incidents table
        conn.execute("""
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY,
                ts TEXT,
                type TEXT,
                ip TEXT,
                user TEXT,
                endpoint TEXT,
                severity TEXT,
                summary TEXT,
                recs TEXT,
                evidence TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Insert some test data
        conn.execute("""
            INSERT INTO incidents (id, ts, type, ip, user, endpoint, severity, summary, recs, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "test-incident-1",
            datetime.now().isoformat(),
            "bruteforce",
            "45.33.32.156",
            "admin",
            "/login",
            "high",
            "Brute force attack detected",
            json.dumps(["Block IP address"]),
            json.dumps(["Multiple failed attempts"])
        ))
        conn.commit()
        return conn
    return original_connect(database)

sqlite3.connect = mock_connect

# Mock get_kb to avoid FAISS errors
class MockKB:
    def get_total_chunks(self):
        return 42

sys.modules['mcp_tools.kb'] = type(sys)('mock_kb')

def mock_get_kb():
    return MockKB()

sys.modules['mcp_tools.kb'].get_kb = mock_get_kb

# Now we can import the API
from app.api import app

class TestAPI:
    @pytest.fixture
    def client(self):
        """Create a test client"""
        return TestClient(app)
    
    def test_health_check(self, client):
        """Test health endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "1.0.0"
    
    def test_get_stats(self, client):
        """Test statistics endpoint"""
        response = client.get("/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "knowledge_base" in data
        assert "security_actions" in data
        assert "timestamp" in data
        
        # Verify incidents structure
        assert "total" in data["incidents"]
        assert "recent_24h" in data["incidents"]
        assert "by_severity" in data["incidents"]
        assert "by_type" in data["incidents"]
        
        # Verify knowledge base
        assert data["knowledge_base"]["total_chunks"] == 42
    
    def test_get_incidents(self, client):
        """Test incident retrieval"""
        response = client.get("/incidents")
        
        assert response.status_code == 200
        incidents = response.json()
        assert isinstance(incidents, list)
        assert len(incidents) > 0
        
        # Verify first incident structure
        incident = incidents[0]
        assert "id" in incident
        assert "ts" in incident
        assert "type" in incident
        assert "entities" in incident
        assert "severity" in incident
        assert "summary" in incident
        assert "recommendations" in incident
        assert "evidence" in incident
    
    def test_get_incidents_with_filters(self, client):
        """Test incident retrieval with filters"""
        # Test severity filter
        response = client.get("/incidents?severity=high")
        assert response.status_code == 200
        
        # Test type filter
        response = client.get("/incidents?incident_type=bruteforce")
        assert response.status_code == 200
        
        # Test with limit
        response = client.get("/incidents?limit=5")
        assert response.status_code == 200
    
    def test_get_incident_by_id(self, client):
        """Test specific incident retrieval"""
        response = client.get("/incidents/test-incident-1")
        
        assert response.status_code == 200
        incident = response.json()
        assert incident["id"] == "test-incident-1"
        assert incident["type"] == "bruteforce"
        assert incident["severity"] == "high"
    
    def test_get_incident_not_found(self, client):
        """Test incident not found"""
        response = client.get("/incidents/nonexistent-id")
        
        assert response.status_code == 404
        error = response.json()
        assert "error" in error
        assert error["error"]["code"] == 404
        assert "not found" in error["error"]["message"].lower()
    
    def test_scan_logs(self, client):
        """Test log scanning"""
        scan_request = {
            "window_hours": 24,
            "rules": ["bruteforce", "spike5xx"]
        }
        
        response = client.post("/scan", json=scan_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "scan_window_hours" in data
        assert "total_incidents" in data
        assert "timestamp" in data
        assert data["scan_window_hours"] == 24
    
    def test_ingest_logs(self, client):
        """Test log ingestion"""
        # Create temporary log file
        log_content = """192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024
45.33.32.156 - - [01/Jan/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 256"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_file_path = f.name
        
        try:
            with open(temp_file_path, 'rb') as f:
                response = client.post(
                    "/ingest",
                    files={"file": ("test.log", f, "text/plain")}
                )
            
            assert response.status_code == 200
            data = response.json()
            assert "processed_count" in data
            assert "indexed_count" in data
            assert "message" in data
        
        finally:
            os.unlink(temp_file_path)
    
    def test_ingest_invalid_file_type(self, client):
        """Test ingestion with invalid file type"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            temp_file_path = f.name
        
        try:
            with open(temp_file_path, 'rb') as f:
                response = client.post(
                    "/ingest",
                    files={"file": ("test.txt", f, "text/plain")}
                )
            
            assert response.status_code == 400
            error = response.json()
            assert "error" in error
            # Error format may vary, just verify there's an error
            assert error["error"]["code"] == 400
        
        finally:
            os.unlink(temp_file_path)
    
    def test_block_ip_action(self, client):
        """Test IP blocking"""
        response = client.post("/actions/block-ip?ip=45.33.32.156&reason=Test block")
        
        assert response.status_code == 200
        result = response.json()
        assert result["action_type"] == "block_ip"
        assert result["target"] == "45.33.32.156"
        assert result["success"] is True
        assert "blocked successfully" in result["message"]
    
    def test_unblock_ip_action(self, client):
        """Test IP unblocking"""
        response = client.post("/actions/unblock-ip?ip=45.33.32.156")
        
        assert response.status_code == 200
        result = response.json()
        assert result["action_type"] == "unblock_ip"
        assert result["target"] == "45.33.32.156"
        assert result["success"] is True
    
    def test_rate_limit_ip_action(self, client):
        """Test IP rate limiting"""
        response = client.post("/actions/rate-limit-ip?ip=45.33.32.156&requests_per_minute=5")
        
        assert response.status_code == 200
        result = response.json()
        assert result["action_type"] == "rate_limit_ip"
        assert result["target"] == "45.33.32.156"
        assert result["success"] is True
    
    def test_reset_tokens_action(self, client):
        """Test token reset"""
        response = client.post("/actions/reset-tokens?user=testuser")
        
        assert response.status_code == 200
        result = response.json()
        assert result["action_type"] == "reset_tokens"
        assert result["target"] == "testuser"
        assert result["success"] is True
    
    def test_get_blocked_ips(self, client):
        """Test blocked IPs retrieval"""
        response = client.get("/actions/blocked-ips")
        
        assert response.status_code == 200
        data = response.json()
        assert "blocked_ips" in data
        assert "count" in data
        assert "timestamp" in data
        assert isinstance(data["blocked_ips"], list)
        assert data["count"] == len(data["blocked_ips"])
    
    def test_get_action_history(self, client):
        """Test action history retrieval"""
        response = client.get("/actions/history")
        
        assert response.status_code == 200
        data = response.json()
        assert "actions" in data
        assert "count" in data
        assert isinstance(data["actions"], list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])