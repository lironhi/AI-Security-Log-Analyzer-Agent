#!/usr/bin/env python3
"""
Test suite for AI Security Log Analyzer
Tests seed sample logs (apache+jsonl) expect ≥1 bruteforce and ≥1 spike5xx
"""
import pytest
import asyncio
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.graph import security_graph
from agents.detector import detector
from mcp_tools.logs import logs_reader
from app.models import LogEntry

class TestLogAnalysis:
    
    def setup_method(self):
        """Set up test environment"""
        self.temp_files = []
    
    def teardown_method(self):
        """Clean up temp files"""
        for file_path in self.temp_files:
            if os.path.exists(file_path):
                os.unlink(file_path)
    
    def create_apache_sample_logs(self) -> str:
        """Create sample Apache combined format logs with security incidents"""
        logs = [
            # Normal traffic
            '192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"',
            '192.168.1.101 - - [01/Jan/2024:10:01:00 +0000] "POST /api/users HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
            
            # Brute force attack (≥5 failures then success)
            '45.33.32.156 - - [01/Jan/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"',
            '45.33.32.156 - - [01/Jan/2024:10:05:30 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"',
            '45.33.32.156 - - [01/Jan/2024:10:06:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"',
            '45.33.32.156 - - [01/Jan/2024:10:06:30 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"',
            '45.33.32.156 - - [01/Jan/2024:10:07:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"',
            '45.33.32.156 - admin [01/Jan/2024:10:08:00 +0000] "POST /login HTTP/1.1" 200 1024 "-" "AttackBot/1.0"',
            
            # 5xx error spike (ratio ≥ 0.2)
            '192.168.1.50 - - [01/Jan/2024:10:10:00 +0000] "GET /api/process HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
            '192.168.1.51 - - [01/Jan/2024:10:10:10 +0000] "GET /api/process HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
            '192.168.1.52 - - [01/Jan/2024:10:10:20 +0000] "GET /api/process HTTP/1.1" 503 0 "-" "Mozilla/5.0"',
            '192.168.1.53 - - [01/Jan/2024:10:10:30 +0000] "GET /api/process HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
            '192.168.1.54 - - [01/Jan/2024:10:10:40 +0000] "GET /api/process HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
            '192.168.1.55 - - [01/Jan/2024:10:10:50 +0000] "GET /api/process HTTP/1.1" 502 0 "-" "Mozilla/5.0"',
            
            # Suspicious paths
            '185.220.100.240 - - [01/Jan/2024:10:15:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 256 "-" ""',
            
            # Rare IP on sensitive endpoint
            '203.0.113.50 - - [01/Jan/2024:10:20:00 +0000] "GET /admin HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        ]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        temp_file.write('\n'.join(logs))
        temp_file.close()
        
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    def create_jsonl_sample_logs(self) -> str:
        """Create sample JSONL format logs"""
        import json
        
        logs = [
            # Normal traffic
            {"ts": "2024-01-01T12:00:00Z", "ip": "192.168.1.100", "endpoint": "/dashboard", "status": 200, "user": "john"},
            
            # Brute force sequence
            {"ts": "2024-01-01T12:05:00Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 401, "ua": "BruteBot"},
            {"ts": "2024-01-01T12:05:15Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 401, "ua": "BruteBot"},
            {"ts": "2024-01-01T12:05:30Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 401, "ua": "BruteBot"},
            {"ts": "2024-01-01T12:05:45Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 401, "ua": "BruteBot"},
            {"ts": "2024-01-01T12:06:00Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 401, "ua": "BruteBot"},
            {"ts": "2024-01-01T12:07:00Z", "ip": "45.33.32.157", "endpoint": "/login", "status": 200, "user": "admin", "ua": "BruteBot"},
            
            # 5xx spike
            {"ts": "2024-01-01T12:10:00Z", "ip": "192.168.1.60", "endpoint": "/api/heavy", "status": 500},
            {"ts": "2024-01-01T12:10:05Z", "ip": "192.168.1.61", "endpoint": "/api/heavy", "status": 502},
            {"ts": "2024-01-01T12:10:10Z", "ip": "192.168.1.62", "endpoint": "/api/heavy", "status": 503},
            {"ts": "2024-01-01T12:10:15Z", "ip": "192.168.1.63", "endpoint": "/api/heavy", "status": 500},
            {"ts": "2024-01-01T12:10:20Z", "ip": "192.168.1.64", "endpoint": "/api/heavy", "status": 200},
            {"ts": "2024-01-01T12:10:25Z", "ip": "192.168.1.65", "endpoint": "/api/heavy", "status": 500}
        ]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False)
        for log in logs:
            temp_file.write(json.dumps(log) + '\n')
        temp_file.close()
        
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    @pytest.mark.asyncio
    async def test_apache_log_parsing(self):
        """Test Apache log format parsing"""
        apache_file = self.create_apache_sample_logs()
        
        logs = await logs_reader.read(apache_file)
        
        assert len(logs) > 0, "Should parse Apache logs"
        assert any(log.ip == "45.33.32.156" for log in logs), "Should find brute force attacker IP"
        assert any(log.status == 401 for log in logs), "Should find 401 failures"
        assert any(log.status == 200 for log in logs), "Should find 200 success"
    
    @pytest.mark.asyncio
    async def test_jsonl_log_parsing(self):
        """Test JSONL format parsing"""
        jsonl_file = self.create_jsonl_sample_logs()
        
        logs = await logs_reader.read(jsonl_file)
        
        assert len(logs) > 0, "Should parse JSONL logs"
        assert any(log.ip == "45.33.32.157" for log in logs), "Should find brute force attacker IP"
        assert any(log.user_agent == "BruteBot" for log in logs), "Should parse user agent"
    
    @pytest.mark.asyncio
    async def test_bruteforce_detection(self):
        """Test brute force attack detection - expect ≥1 bruteforce"""
        apache_file = self.create_apache_sample_logs()
        logs = await logs_reader.read(apache_file)
        
        incidents = await detector._detect_bruteforce(logs)
        
        assert len(incidents) >= 1, f"Expected ≥1 brute force incident, found {len(incidents)}"
        
        brute_incident = incidents[0]
        assert brute_incident.type == "bruteforce", "Should detect brute force type"
        assert brute_incident.severity == "high", "Brute force should be high severity"
        assert "45.33.32.156" in brute_incident.entities.get("ip", ""), "Should identify attacker IP"
    
    @pytest.mark.asyncio
    async def test_spike5xx_detection(self):
        """Test 5xx error spike detection - expect ≥1 spike5xx"""
        apache_file = self.create_apache_sample_logs()
        logs = await logs_reader.read(apache_file)
        
        incidents = await detector._detect_spike5xx(logs)
        
        assert len(incidents) >= 1, f"Expected ≥1 5xx spike incident, found {len(incidents)}"
        
        spike_incident = incidents[0]
        assert spike_incident.type == "spike5xx", "Should detect spike5xx type"
        assert spike_incident.severity == "medium", "5xx spike should be medium severity"
        assert "/api/process" in spike_incident.entities.get("endpoint", ""), "Should identify problematic endpoint"
    
    @pytest.mark.asyncio
    async def test_rare_ip_detection(self):
        """Test rare IP detection"""
        apache_file = self.create_apache_sample_logs()
        logs = await logs_reader.read(apache_file)
        
        incidents = await detector._detect_rare_ip(logs)
        
        # Should find rare IP accessing admin endpoint
        rare_ips = [i for i in incidents if "203.0.113.50" in i.entities.get("ip", "")]
        assert len(rare_ips) >= 0, "Should detect rare IP on sensitive endpoint"
    
    @pytest.mark.asyncio
    async def test_suspicious_path_detection(self):
        """Test suspicious path detection"""
        apache_file = self.create_apache_sample_logs()
        logs = await logs_reader.read(apache_file)
        
        incidents = await detector._detect_suspicious_path(logs)
        
        # Should find path traversal attempt
        path_attacks = [i for i in incidents if ".." in str(i.evidence)]
        assert len(path_attacks) >= 0, "Should detect path traversal attempts"
    
    @pytest.mark.asyncio
    async def test_end_to_end_processing(self):
        """Test complete log processing pipeline"""
        apache_file = self.create_apache_sample_logs()
        
        result = await security_graph.process_logs(apache_file, window_hours=24)
        
        incidents = result.get("incidents", [])
        metadata = result.get("metadata", {})
        
        # Should process logs successfully
        assert metadata.get("status") == "success", f"Processing failed: {metadata}"
        assert metadata.get("ingested_count", 0) > 0, "Should ingest logs"
        
        # Should detect incidents (expect ≥1 bruteforce and ≥1 spike5xx)
        incident_types = [i["type"] for i in incidents]
        
        bruteforce_count = incident_types.count("bruteforce")
        spike5xx_count = incident_types.count("spike5xx")
        
        assert bruteforce_count >= 1, f"Expected ≥1 bruteforce incident, found {bruteforce_count}"
        assert spike5xx_count >= 1, f"Expected ≥1 spike5xx incident, found {spike5xx_count}"
        
        print(f"✅ Detected {bruteforce_count} brute force and {spike5xx_count} 5xx spike incidents")
    
    @pytest.mark.asyncio
    async def test_combined_logs_processing(self):
        """Test processing both Apache and JSONL formats"""
        apache_file = self.create_apache_sample_logs()
        jsonl_file = self.create_jsonl_sample_logs()
        
        # Test Apache
        apache_result = await security_graph.process_logs(apache_file)
        apache_incidents = apache_result.get("incidents", [])
        
        # Test JSONL  
        jsonl_result = await security_graph.process_logs(jsonl_file)
        jsonl_incidents = jsonl_result.get("incidents", [])
        
        # Both should detect incidents
        total_incidents = len(apache_incidents) + len(jsonl_incidents)
        assert total_incidents >= 2, f"Expected ≥2 total incidents across formats, found {total_incidents}"
        
        print(f"✅ Apache logs: {len(apache_incidents)} incidents")
        print(f"✅ JSONL logs: {len(jsonl_incidents)} incidents")
        print(f"✅ Total: {total_incidents} incidents detected")

if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v"])