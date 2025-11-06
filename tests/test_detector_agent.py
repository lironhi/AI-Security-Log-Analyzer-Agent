#!/usr/bin/env python3
"""
Tests for the security detection agent
"""
import pytest
from datetime import datetime, timedelta

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import LogEntry, Incident

class MockLLM:
    """Mock for ChatOpenAI"""
    def __init__(self, *args, **kwargs):
        pass
    
    async def ainvoke(self, messages):
        class MockResponse:
            content = '[]'  # Returns empty list of JSON incidents
        return MockResponse()

# Mock all langchain dependencies before importing
class MockHumanMessage:
    def __init__(self, content):
        self.content = content

sys.modules['langchain'] = type(sys)('mock_langchain')
sys.modules['langchain.schema'] = type(sys)('mock_schema')
sys.modules['langchain.schema'].BaseMessage = object
sys.modules['langchain.schema'].HumanMessage = MockHumanMessage
sys.modules['langchain_openai'] = type(sys)('mock_openai')
sys.modules['langchain_openai'].ChatOpenAI = MockLLM

from agents.detector import DetectorAgent

class TestDetectorAgent:
    
    @pytest.fixture
    def detector(self):
        """Create an instance of the detector agent"""
        return DetectorAgent()
    
    @pytest.fixture
    def sample_logs(self):
        """Create sample logs for tests"""
        base_time = datetime.now()
        return [
            # Normal logs
            LogEntry(
                timestamp=base_time,
                ip="192.168.1.100",
                endpoint="/dashboard",
                status=200,
                method="GET",
                user="john",
                user_agent="Mozilla/5.0"
            ),
            LogEntry(
                timestamp=base_time + timedelta(minutes=1),
                ip="192.168.1.101",
                endpoint="/api/data",
                status=200,
                method="GET",
                user="alice",
                user_agent="Mozilla/5.0"
            ),
        ]
    
    @pytest.fixture
    def bruteforce_logs(self):
        """Create logs simulating a brute force attack"""
        base_time = datetime.now()
        attacker_ip = "45.33.32.156"
        logs = []
        
        # 6 failed attempts
        for i in range(6):
            logs.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i * 15),
                ip=attacker_ip,
                endpoint="/login",
                status=401,
                method="POST",
                user_agent="AttackBot/1.0"
            ))
        
        # One successful attempt
        logs.append(LogEntry(
            timestamp=base_time + timedelta(seconds=90),
            ip=attacker_ip,
            endpoint="/login",
            status=200,
            method="POST",
            user="admin",
            user_agent="AttackBot/1.0"
        ))
        
        return logs
    
    @pytest.fixture
    def spike_5xx_logs(self):
        """Create logs simulating a 5xx error spike"""
        base_time = datetime.now()
        logs = []
        
        # 8 5xx errors and 2 successes (80% error rate)
        for i in range(8):
            logs.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i * 10),
                ip=f"192.168.1.{100 + i}",
                endpoint="/api/process",
                status=500,
                method="GET",
                user_agent="Mozilla/5.0"
            ))
        
        for i in range(2):
            logs.append(LogEntry(
                timestamp=base_time + timedelta(seconds=(8 + i) * 10),
                ip=f"192.168.1.{108 + i}",
                endpoint="/api/process",
                status=200,
                method="GET",
                user_agent="Mozilla/5.0"
            ))
        
        return logs
    
    @pytest.fixture
    def rare_ip_logs(self):
        """Create logs simulating a rare IP on a sensitive endpoint"""
        base_time = datetime.now()
        return [
            LogEntry(
                timestamp=base_time,
                ip="203.0.113.50",  # Rare IP
                endpoint="/admin/dashboard",
                status=200,
                method="GET",
                user_agent="Mozilla/5.0"
            ),
            LogEntry(
                timestamp=base_time + timedelta(minutes=1),
                ip="203.0.113.50",
                endpoint="/admin/users",
                status=200,
                method="GET",
                user_agent="Mozilla/5.0"
            ),
        ]
    
    @pytest.fixture
    def suspicious_path_logs(self):
        """Create logs with suspicious paths"""
        base_time = datetime.now()
        return [
            # Directory traversal
            LogEntry(
                timestamp=base_time,
                ip="185.220.100.240",
                endpoint="/admin/../../../etc/passwd",
                status=403,
                method="GET",
                user_agent=""  # Empty user agent
            ),
            # Request with long query string
            LogEntry(
                timestamp=base_time + timedelta(seconds=30),
                ip="185.220.100.241",
                endpoint="/search?" + "x" * 600,  # Very long query string
                status=200,
                method="GET",
                user_agent="Mozilla/5.0"
            ),
        ]
    
    @pytest.mark.asyncio
    async def test_bruteforce_detection(self, detector, bruteforce_logs):
        """Test brute force attack detection"""
        incidents = await detector._detect_bruteforce(bruteforce_logs)
        
        assert len(incidents) == 1, f"Expected 1 brute force incident, got {len(incidents)}"
        
        incident = incidents[0]
        assert incident.type == "bruteforce"
        assert incident.severity == "high"
        assert incident.entities["ip"] == "45.33.32.156"
        assert incident.entities["user"] == "admin"
        assert incident.entities["endpoint"] == "/login"
        
        # Verify evidence
        evidence_text = " ".join(incident.evidence)
        assert "6 failed attempts" in evidence_text
        assert "45.33.32.156" in evidence_text
        assert "Successful login" in evidence_text
    
    @pytest.mark.asyncio
    async def test_no_bruteforce_without_success(self, detector):
        """Test that no brute force is detected without final success"""
        base_time = datetime.now()
        attacker_ip = "45.33.32.156"
        logs = []
        
        # Only failures, no success
        for i in range(10):
            logs.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i * 15),
                ip=attacker_ip,
                endpoint="/login",
                status=401,
                method="POST"
            ))
        
        incidents = await detector._detect_bruteforce(logs)
        assert len(incidents) == 0, "Should not detect brute force without final success"
    
    @pytest.mark.asyncio
    async def test_spike_5xx_detection(self, detector, spike_5xx_logs):
        """Test 5xx error spike detection"""
        incidents = await detector._detect_spike5xx(spike_5xx_logs)
        
        assert len(incidents) == 1, f"Expected 1 5xx spike incident, got {len(incidents)}"
        
        incident = incidents[0]
        assert incident.type == "spike5xx"
        assert incident.severity == "medium"
        assert incident.entities["endpoint"] == "/api/process"
        
        # Verify evidence
        evidence_text = " ".join(incident.evidence)
        # Error rate may vary depending on window grouping
        assert "%" in evidence_text  # Verify there's a percentage
        assert "/api/process" in evidence_text
        # Verify error rate is high (>= 20%)
        assert "Threshold exceeded" in evidence_text
    
    @pytest.mark.asyncio
    async def test_no_spike_5xx_below_threshold(self, detector):
        """Test that no 5xx spike is detected below threshold"""
        base_time = datetime.now()
        logs = []
        
        # 1 5xx error and 9 successes (10% error < 20% threshold)
        logs.append(LogEntry(
            timestamp=base_time,
            ip="192.168.1.100",
            endpoint="/api/test",
            status=500,
            method="GET"
        ))
        
        for i in range(9):
            logs.append(LogEntry(
                timestamp=base_time + timedelta(seconds=(i + 1) * 10),
                ip=f"192.168.1.{100 + i}",
                endpoint="/api/test",
                status=200,
                method="GET"
            ))
        
        incidents = await detector._detect_spike5xx(logs)
        assert len(incidents) == 0, "Should not detect 5xx spike below threshold"
    
    @pytest.mark.asyncio
    async def test_rare_ip_detection(self, detector, rare_ip_logs):
        """Test rare IP detection"""
        incidents = await detector._detect_rare_ip(rare_ip_logs)
        
        assert len(incidents) == 1, f"Expected 1 rare IP incident, got {len(incidents)}"
        
        incident = incidents[0]
        assert incident.type == "rare_ip"
        assert incident.severity == "medium"
        assert incident.entities["ip"] == "203.0.113.50"
        assert "/admin" in incident.entities["endpoint"]
        
        # Verify evidence
        evidence_text = " ".join(incident.evidence)
        assert "203.0.113.50" in evidence_text
        assert "sensitive endpoint" in evidence_text
        assert "2 times" in evidence_text  # IP appears 2 times
    
    @pytest.mark.asyncio
    async def test_suspicious_path_detection(self, detector, suspicious_path_logs):
        """Test suspicious path detection"""
        incidents = await detector._detect_suspicious_path(suspicious_path_logs)
        
        assert len(incidents) >= 1, f"Expected at least 1 suspicious path incident, got {len(incidents)}"
        
        # Find directory traversal incident
        traversal_incident = None
        for incident in incidents:
            if ".." in " ".join(incident.evidence):
                traversal_incident = incident
                break
        
        assert traversal_incident is not None, "Should detect path traversal"
        assert traversal_incident.type == "suspicious_path"
        assert traversal_incident.severity == "high"
        assert traversal_incident.entities["ip"] == "185.220.100.240"
        
        # Verify evidence
        evidence_text = " ".join(traversal_incident.evidence)
        assert "path_traversal" in evidence_text
        assert "empty_user_agent" in evidence_text
        assert "../../../etc/passwd" in evidence_text
    
    @pytest.mark.asyncio
    async def test_scan_window_integration(self, detector, bruteforce_logs, spike_5xx_logs):
        """Test complete scan over time window"""
        # Combine different types of logs
        all_logs = bruteforce_logs + spike_5xx_logs
        
        incidents = await detector.scan_window(all_logs, window_hours=24)
        
        # Should detect at least one brute force and one 5xx spike
        incident_types = [i.type for i in incidents]
        assert "bruteforce" in incident_types, "Should detect brute force in scan"
        assert "spike5xx" in incident_types, "Should detect 5xx spike in scan"
        
        assert len(incidents) >= 2, f"Expected at least 2 incidents, got {len(incidents)}"
    
    @pytest.mark.asyncio
    async def test_scan_window_time_filtering(self, detector, sample_logs):
        """Test that scan correctly filters by time window"""
        # Create old logs (outside window)
        old_time = datetime.now() - timedelta(days=2)
        old_logs = [
            LogEntry(
                timestamp=old_time,
                ip="45.33.32.156",
                endpoint="/login",
                status=401,
                method="POST"
            )
        ]
        
        all_logs = sample_logs + old_logs
        
        # Scan with 24-hour window
        incidents = await detector.scan_window(all_logs, window_hours=24)
        
        # Old logs should not generate incidents
        for incident in incidents:
            # Verify no incident references old logs
            evidence_text = " ".join(incident.evidence)
            assert old_time.date().isoformat() not in evidence_text
    
    @pytest.mark.asyncio
    async def test_analyze_with_llm_mock(self, detector, sample_logs):
        """Test LLM analysis (mocked)"""
        # This function uses a mock LLM that returns []
        incidents = await detector.analyze_with_llm(sample_logs)
        
        assert isinstance(incidents, list), "LLM analysis should return a list"
        # Mock returns empty list
        assert len(incidents) == 0, "Mock LLM should return empty list"
    
    def test_create_log_summary(self, detector, sample_logs):
        """Test log summary creation"""
        summary = detector._create_log_summary(sample_logs)
        
        assert isinstance(summary, str), "Summary should be a string"
        assert len(summary) > 0, "Summary should not be empty"
        
        # Verify summary contains key elements
        assert "192.168.1.100" in summary
        assert "/dashboard" in summary
        assert "200" in summary
        assert "john" in summary

if __name__ == "__main__":
    pytest.main([__file__, "-v"])