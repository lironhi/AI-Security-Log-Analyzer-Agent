#!/usr/bin/env python3
"""
Tests pour l'agent investigateur et l'intelligence IP
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, Mock

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import Incident, InvestigationContext, LogEntry

# Mock des dépendances externes
class MockLLM:
    def __init__(self, *args, **kwargs):
        pass
    
    async def ainvoke(self, messages):
        class MockResponse:
            content = '''
            {
                "ip_analysis": "IP 45.33.32.156 appears to be from a known attack source",
                "user_behavior": "User admin shows suspicious login patterns",
                "timeline_analysis": "Attack occurred during off-hours",
                "correlation_found": true,
                "additional_context": "This IP has been flagged in threat intelligence feeds"
            }
            '''
        return MockResponse()

class MockIntelProvider:
    async def get_ip_info(self, ip):
        if ip == "45.33.32.156":
            return {
                "country": "Unknown",
                "is_tor": True,
                "is_vpn": False,
                "reputation": "malicious",
                "asn": "AS12345",
                "organization": "Suspicious Hosting"
            }
        return {
            "country": "US",
            "is_tor": False,
            "is_vpn": False,
            "reputation": "clean",
            "asn": "AS1234",
            "organization": "Legitimate ISP"
        }
    
    async def check_threat_feeds(self, ip):
        if ip == "45.33.32.156":
            return {
                "found_in_feeds": True,
                "categories": ["malware", "botnet"],
                "last_seen": "2024-01-01T10:00:00Z",
                "confidence": "high"
            }
        return {
            "found_in_feeds": False,
            "categories": [],
            "confidence": "low"
        }

class MockKB:
    async def search_similar(self, query, limit=5):
        # Simuler des logs similaires trouvés
        return [
            {
                "content": "Similar incident: IP 45.33.32.156 attempted brute force on 2023-12-15",
                "metadata": {"ip": "45.33.32.156", "date": "2023-12-15"},
                "score": 0.95
            },
            {
                "content": "Related: Same IP accessed admin panel multiple times",
                "metadata": {"ip": "45.33.32.156", "endpoint": "/admin"},
                "score": 0.87
            }
        ]

# Mock les modules avant d'importer
sys.modules['langchain_openai'] = type(sys)('mock_openai')
sys.modules['langchain_openai'].ChatOpenAI = MockLLM
sys.modules['mcp_tools.intel'] = type(sys)('mock_intel')
sys.modules['mcp_tools.intel'].intel_provider = MockIntelProvider()
sys.modules['mcp_tools.kb'] = type(sys)('mock_kb')
sys.modules['mcp_tools.kb'].get_kb = lambda: MockKB()

from agents.investigator import InvestigatorAgent

class TestInvestigatorAgent:
    
    @pytest.fixture
    def investigator(self):
        """Créer une instance de l'agent investigateur"""
        return InvestigatorAgent()
    
    @pytest.fixture
    def sample_incident(self):
        """Créer un incident d'exemple pour investigation"""
        return Incident(
            id="test-incident-1",
            type="bruteforce",
            severity="high",
            summary="Brute force attack detected from IP 45.33.32.156",
            entities={
                "ip": "45.33.32.156",
                "user": "admin",
                "endpoint": "/login"
            },
            evidence=[
                "5 failed login attempts",
                "Successful login after attempts",
                "User agent: AttackBot/1.0"
            ]
        )
    
    @pytest.fixture
    def related_logs(self):
        """Créer des logs liés pour le contexte"""
        base_time = datetime.now()
        return [
            LogEntry(
                timestamp=base_time,
                ip="45.33.32.156",
                endpoint="/login",
                status=401,
                method="POST",
                user_agent="AttackBot/1.0"
            ),
            LogEntry(
                timestamp=base_time,
                ip="45.33.32.156",
                endpoint="/admin",
                status=403,
                method="GET",
                user_agent="AttackBot/1.0"
            )
        ]
    
    @pytest.mark.asyncio
    async def test_investigate_incident(self, investigator, sample_incident):
        """Test investigation complète d'un incident"""
        context = await investigator.investigate(sample_incident)
        
        assert isinstance(context, InvestigationContext)
        assert context.incident_id == sample_incident.id
        assert context.ip_intelligence is not None
        assert context.threat_intelligence is not None
        
        # Vérifier l'intelligence IP
        ip_intel = context.ip_intelligence
        assert ip_intel["country"] == "Unknown"
        assert ip_intel["is_tor"] is True
        assert ip_intel["reputation"] == "malicious"
        
        # Vérifier l'intelligence des menaces
        threat_intel = context.threat_intelligence
        assert threat_intel["found_in_feeds"] is True
        assert "malware" in threat_intel["categories"]
        assert threat_intel["confidence"] == "high"
    
    @pytest.mark.asyncio
    async def test_gather_ip_intelligence(self, investigator):
        """Test collecte d'intelligence sur IP"""
        # Test IP malveillante
        ip_info = await investigator._gather_ip_intelligence("45.33.32.156")
        
        assert ip_info["country"] == "Unknown"
        assert ip_info["is_tor"] is True
        assert ip_info["reputation"] == "malicious"
        assert ip_info["organization"] == "Suspicious Hosting"
        
        # Test IP légitime
        clean_ip_info = await investigator._gather_ip_intelligence("192.168.1.100")
        assert clean_ip_info["country"] == "US"
        assert clean_ip_info["is_tor"] is False
        assert clean_ip_info["reputation"] == "clean"
    
    @pytest.mark.asyncio
    async def test_search_related_incidents(self, investigator, sample_incident):
        """Test recherche d'incidents liés"""
        similar_incidents = await investigator._search_related_incidents(sample_incident)
        
        assert isinstance(similar_incidents, list)
        assert len(similar_incidents) == 2
        
        # Vérifier le contenu
        first_incident = similar_incidents[0]
        assert "45.33.32.156" in first_incident["content"]
        assert first_incident["score"] == 0.95
        assert first_incident["metadata"]["ip"] == "45.33.32.156"
    
    @pytest.mark.asyncio
    async def test_analyze_user_behavior(self, investigator, sample_incident, related_logs):
        """Test analyse du comportement utilisateur"""
        user_analysis = await investigator._analyze_user_behavior(
            sample_incident, related_logs
        )
        
        assert isinstance(user_analysis, dict)
        assert "login_patterns" in user_analysis
        assert "access_patterns" in user_analysis
        assert "risk_score" in user_analysis
        
        # Vérifier les patterns détectés
        assert user_analysis["user"] == "admin"
        assert len(user_analysis["failed_attempts"]) > 0
    
    @pytest.mark.asyncio
    async def test_create_timeline(self, investigator, sample_incident, related_logs):
        """Test création de timeline"""
        timeline = await investigator._create_timeline(sample_incident, related_logs)
        
        assert isinstance(timeline, list)
        assert len(timeline) > 0
        
        # Vérifier la structure des événements
        for event in timeline:
            assert "timestamp" in event
            assert "event_type" in event
            assert "description" in event
            assert "severity" in event
    
    @pytest.mark.asyncio
    async def test_correlate_with_llm(self, investigator, sample_incident):
        """Test corrélation avec LLM"""
        correlation = await investigator._correlate_with_llm(
            sample_incident, 
            ip_intelligence={"reputation": "malicious", "is_tor": True},
            similar_incidents=[]
        )
        
        assert isinstance(correlation, dict)
        assert "ip_analysis" in correlation
        assert "correlation_found" in correlation
        assert correlation["correlation_found"] is True
    
    @pytest.mark.asyncio
    async def test_investigation_error_handling(self, investigator):
        """Test gestion des erreurs pendant l'investigation"""
        # Incident sans IP
        incident_without_ip = Incident(
            type="spike5xx",
            severity="medium",
            summary="Server errors detected",
            entities={"endpoint": "/api/test"}
        )
        
        context = await investigator.investigate(incident_without_ip)
        
        # Devrait fonctionner même sans IP
        assert isinstance(context, InvestigationContext)
        assert context.incident_id == incident_without_ip.id
        assert context.ip_intelligence is None  # Pas d'IP à analyser
    
    @pytest.mark.asyncio
    async def test_investigation_context_enrichment(self, investigator, sample_incident):
        """Test enrichissement du contexte d'investigation"""
        context = await investigator.investigate(sample_incident)
        
        # Vérifier que le contexte est enrichi
        assert len(context.related_logs) > 0
        assert len(context.timeline) > 0
        assert context.user_context is not None
        assert context.correlation_results is not None
        
        # Vérifier les métriques de confiance
        assert "confidence_score" in context.correlation_results
        assert 0 <= context.correlation_results["confidence_score"] <= 1
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_integration(self, investigator):
        """Test intégration avec les flux de threat intelligence"""
        threat_info = await investigator._check_threat_intelligence("45.33.32.156")
        
        assert threat_info["found_in_feeds"] is True
        assert isinstance(threat_info["categories"], list)
        assert len(threat_info["categories"]) > 0
        assert threat_info["confidence"] in ["low", "medium", "high"]
        assert "last_seen" in threat_info
    
    def test_risk_scoring(self, investigator):
        """Test calcul du score de risque"""
        risk_factors = {
            "is_tor": True,
            "reputation": "malicious",
            "failed_attempts": 5,
            "successful_login": True,
            "threat_feeds": True,
            "geographic_anomaly": False
        }
        
        risk_score = investigator._calculate_risk_score(risk_factors)
        
        assert isinstance(risk_score, float)
        assert 0.0 <= risk_score <= 1.0
        assert risk_score > 0.7  # Devrait être élevé avec ces facteurs

if __name__ == "__main__":
    pytest.main([__file__, "-v"])