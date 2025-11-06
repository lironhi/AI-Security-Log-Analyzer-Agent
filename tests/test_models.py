#!/usr/bin/env python3
"""
Unit tests for Pydantic models
"""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import (
    LogEntry, LogChunk, Incident, DetectionRule, 
    InvestigationContext, ActionResult, ScanRequest, IngestResponse
)

class TestLogEntry:
    def test_log_entry_creation(self):
        """Test basic log entry creation"""
        log = LogEntry(
            timestamp=datetime.now(),
            ip="192.168.1.1",
            endpoint="/api/test",
            status=200
        )
        
        assert log.ip == "192.168.1.1"
        assert log.endpoint == "/api/test"
        assert log.status == 200
        assert log.method == "GET"  # default value
        assert log.user is None
        
    def test_log_entry_with_all_fields(self):
        """Test creation of a complete log entry"""
        timestamp = datetime.now()
        
        log = LogEntry(
            timestamp=timestamp,
            ip="45.33.32.156",
            user="admin",
            endpoint="/login",
            status=401,
            method="POST",
            user_agent="AttackBot/1.0",
            payload_size=256,
            response_time=1.5
        )
        
        assert log.timestamp == timestamp
        assert log.ip == "45.33.32.156"
        assert log.user == "admin"
        assert log.endpoint == "/login"
        assert log.status == 401
        assert log.method == "POST"
        assert log.user_agent == "AttackBot/1.0"
        assert log.payload_size == 256
        assert log.response_time == 1.5

class TestIncident:
    def test_incident_creation_with_defaults(self):
        """Test incident creation with default values"""
        incident = Incident(
            type="bruteforce",
            severity="high",
            summary="Brute force attempt detected"
        )
        
        assert incident.type == "bruteforce"
        assert incident.severity == "high"
        assert incident.summary == "Brute force attempt detected"
        assert isinstance(incident.id, str)
        assert isinstance(incident.ts, datetime)
        assert incident.entities == {}
        assert incident.evidence == []
        assert incident.recommendations == []
        
    def test_incident_with_complete_data(self):
        """Test creation of a complete incident"""
        incident = Incident(
            type="spike5xx",
            severity="medium",
            summary="5xx error spike detected",
            entities={"ip": "192.168.1.1", "endpoint": "/api/process"},
            evidence=["Error rate: 60%", "10 5xx errors in 2 minutes"],
            recommendations=["Check server load", "Analyze application logs"]
        )
        
        assert incident.type == "spike5xx"
        assert incident.severity == "medium"
        assert incident.entities["ip"] == "192.168.1.1"
        assert incident.entities["endpoint"] == "/api/process"
        assert len(incident.evidence) == 2
        assert len(incident.recommendations) == 2
        
    def test_incident_type_validation(self):
        """Test incident type validation"""
        # Types valides
        valid_types = ["bruteforce", "spike5xx", "rare_ip", "suspicious_path"]
        
        for incident_type in valid_types:
            incident = Incident(
                type=incident_type,
                severity="low",
                summary=f"Test {incident_type}"
            )
            assert incident.type == incident_type
            
    def test_incident_severity_validation(self):
        """Test severity validation"""
        valid_severities = ["low", "medium", "high"]
        
        for severity in valid_severities:
            incident = Incident(
                type="bruteforce",
                severity=severity,
                summary=f"Test {severity}"
            )
            assert incident.severity == severity

class TestLogChunk:
    def test_log_chunk_creation(self):
        """Test creation d'un chunk de log"""
        chunk = LogChunk(
            content="Log content here",
            metadata={"ip": "192.168.1.1"},
            timestamp=datetime.now()
        )
        
        assert chunk.content == "Log content here"
        assert chunk.metadata["ip"] == "192.168.1.1"
        assert isinstance(chunk.id, str)
        assert chunk.embedding is None
        
    def test_log_chunk_with_embedding(self):
        """Test creation d'un chunk avec embedding"""
        embedding = [0.1, 0.2, 0.3, 0.4, 0.5]
        
        chunk = LogChunk(
            content="Log with embedding",
            metadata={"source": "apache"},
            timestamp=datetime.now(),
            embedding=embedding
        )
        
        assert chunk.embedding == embedding
        assert len(chunk.embedding) == 5

class TestDetectionRule:
    def test_detection_rule_creation(self):
        """Test creation of a detection rule"""
        rule = DetectionRule(
            name="Brute Force Detection",
            description="Detects brute force attempts"
        )
        
        assert rule.name == "Brute Force Detection"
        assert rule.description == "Détecte les tentatives de brute force"
        assert rule.enabled is True  # default value
        assert rule.threshold == {}
        
    def test_detection_rule_with_threshold(self):
        """Test rule with custom threshold"""
        rule = DetectionRule(
            name="5xx Spike Detection",
            description="Detects 5xx error spikes",
            enabled=False,
            threshold={"min_errors": 5, "window_minutes": 10}
        )
        
        assert rule.enabled is False
        assert rule.threshold["min_errors"] == 5
        assert rule.threshold["window_minutes"] == 10

class TestInvestigationContext:
    def test_investigation_context_creation(self):
        """Test creation of an investigation context"""
        log = LogEntry(
            timestamp=datetime.now(),
            ip="192.168.1.1",
            endpoint="/login",
            status=401
        )
        
        context = InvestigationContext(
            incident_id="test-incident-id",
            related_logs=[log]
        )
        
        assert context.incident_id == "test-incident-id"
        assert len(context.related_logs) == 1
        assert context.related_logs[0].ip == "192.168.1.1"
        assert context.ip_intelligence is None
        assert context.user_context is None
        assert context.timeline == []
        
    def test_investigation_context_with_intelligence(self):
        """Test context with IP intelligence"""
        context = InvestigationContext(
            incident_id="test-id",
            related_logs=[],
            ip_intelligence={"country": "Unknown", "is_tor": True},
            user_context={"previous_logins": 5}
        )
        
        assert context.ip_intelligence["country"] == "Unknown"
        assert context.ip_intelligence["is_tor"] is True
        assert context.user_context["previous_logins"] == 5

class TestActionResult:
    def test_action_result_creation(self):
        """Test creation of an action result"""
        result = ActionResult(
            action_type="block_ip",
            target="45.33.32.156",
            success=True,
            message="IP blocked successfully"
        )
        
        assert result.action_type == "block_ip"
        assert result.target == "45.33.32.156"
        assert result.success is True
        assert result.message == "IP blocked successfully"
        assert isinstance(result.timestamp, datetime)
        
    def test_action_result_failure(self):
        """Test failed action result"""
        result = ActionResult(
            action_type="reset_tokens",
            target="user123",
            success=False,
            message="User not found"
        )
        
        assert result.success is False
        assert result.message == "User not found"

class TestScanRequest:
    def test_scan_request_defaults(self):
        """Test scan request with defaults"""
        request = ScanRequest()
        
        assert request.window_hours == 24
        assert request.rules is None
        
    def test_scan_request_custom(self):
        """Test custom scan request"""
        request = ScanRequest(
            window_hours=6,
            rules=["bruteforce", "spike5xx"]
        )
        
        assert request.window_hours == 6
        assert request.rules == ["bruteforce", "spike5xx"]

class TestIngestResponse:
    def test_ingest_response_creation(self):
        """Test creation of an ingestion response"""
        response = IngestResponse(
            processed_count=150,
            indexed_count=145,
            message="File processed successfully"
        )
        
        assert response.processed_count == 150
        assert response.indexed_count == 145
        assert response.message == "File processed successfully"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])