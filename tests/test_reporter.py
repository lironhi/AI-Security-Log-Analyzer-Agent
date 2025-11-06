#!/usr/bin/env python3
"""
Tests pour l'agent reporter et les actions de sécurité
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, Mock

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import Incident, InvestigationContext, LogEntry, ActionResult

# Mock des dépendances
class MockLLM:
    def __init__(self, *args, **kwargs):
        pass
    
    async def ainvoke(self, messages):
        class MockResponse:
            content = '''
            {
                "severity_assessment": "high",
                "confidence_score": 0.92,
                "detailed_summary": "Confirmed brute force attack from malicious IP with successful compromise",
                "recommendations": [
                    "Immediately block IP address 45.33.32.156",
                    "Reset password for compromised user admin",
                    "Review and strengthen authentication policies",
                    "Monitor for lateral movement from compromised account"
                ],
                "priority": "immediate",
                "estimated_impact": "high"
            }
            '''
        return MockResponse()

class MockActions:
    async def block_ip(self, ip, reason="Security incident"):
        return ActionResult(
            action_type="block_ip",
            target=ip,
            success=True,
            message=f"IP {ip} blocked successfully"
        )
    
    async def reset_tokens(self, user, reason="Security incident"):
        return ActionResult(
            action_type="reset_tokens",
            target=user,
            success=True,
            message=f"Tokens reset for user {user}"
        )
    
    async def rate_limit_ip(self, ip, requests_per_minute=10):
        return ActionResult(
            action_type="rate_limit_ip",
            target=ip,
            success=True,
            message=f"Rate limiting applied to {ip}"
        )

# Mock les modules avant d'importer
sys.modules['langchain_openai'] = type(sys)('mock_openai')
sys.modules['langchain_openai'].ChatOpenAI = MockLLM
sys.modules['mcp_tools.actions'] = type(sys)('mock_actions')
sys.modules['mcp_tools.actions'].actions = MockActions()

from agents.reporter import ReporterAgent

class TestReporterAgent:
    
    @pytest.fixture
    def reporter(self):
        """Créer une instance de l'agent reporter"""
        return ReporterAgent()
    
    @pytest.fixture
    def sample_incident(self):
        """Incident d'exemple pour les tests"""
        return Incident(
            id="test-incident-1",
            type="bruteforce",
            severity="medium",  # Will be upgraded by reporter
            summary="Brute force attack detected from IP 45.33.32.156",
            entities={
                "ip": "45.33.32.156",
                "user": "admin",
                "endpoint": "/login"
            },
            evidence=[
                "5 failed login attempts in 2 minutes",
                "Successful login after attempts",
                "User agent indicates automated tool"
            ]
        )
    
    @pytest.fixture
    def investigation_context(self):
        """Contexte d'investigation d'exemple"""
        return InvestigationContext(
            incident_id="test-incident-1",
            related_logs=[
                LogEntry(
                    timestamp=datetime.now(),
                    ip="45.33.32.156",
                    endpoint="/login",
                    status=401,
                    method="POST"
                )
            ],
            ip_intelligence={
                "country": "Unknown",
                "is_tor": True,
                "reputation": "malicious",
                "threat_feeds": True
            },
            threat_intelligence={
                "found_in_feeds": True,
                "categories": ["malware", "botnet"],
                "confidence": "high"
            },
            user_context={
                "user": "admin",
                "failed_attempts": 5,
                "successful_login": True,
                "login_time": "2024-01-01T10:08:00Z"
            },
            timeline=[
                {
                    "timestamp": "2024-01-01T10:05:00Z",
                    "event_type": "failed_login",
                    "description": "Failed login attempt 1"
                },
                {
                    "timestamp": "2024-01-01T10:08:00Z",
                    "event_type": "successful_login",
                    "description": "Successful login"
                }
            ],
            correlation_results={
                "correlation_found": True,
                "confidence_score": 0.92,
                "similar_incidents": 2
            }
        )
    
    @pytest.mark.asyncio
    async def test_generate_report(self, reporter, sample_incident, investigation_context):
        """Test génération de rapport complet"""
        final_incident = await reporter.generate_report(sample_incident, investigation_context)
        
        # Vérifier que l'incident a été enrichi
        assert isinstance(final_incident, Incident)
        assert final_incident.id == sample_incident.id
        
        # Vérifier l'upgrade de sévérité
        assert final_incident.severity == "high"  # Upgraded from medium
        
        # Vérifier les recommandations ajoutées
        assert len(final_incident.recommendations) >= 3
        assert any("block" in rec.lower() for rec in final_incident.recommendations)
        assert any("reset" in rec.lower() for rec in final_incident.recommendations)
        
        # Vérifier le résumé enrichi
        assert len(final_incident.summary) > len(sample_incident.summary)
        assert "malicious" in final_incident.summary.lower() or "confirmed" in final_incident.summary.lower()
    
    @pytest.mark.asyncio
    async def test_assess_severity(self, reporter, sample_incident, investigation_context):
        """Test évaluation de la sévérité"""
        severity, confidence = await reporter._assess_severity(sample_incident, investigation_context)
        
        assert severity in ["low", "medium", "high"]
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
        
        # Avec le contexte fourni, devrait être high
        assert severity == "high"
        assert confidence > 0.8
    
    @pytest.mark.asyncio
    async def test_generate_recommendations(self, reporter, sample_incident, investigation_context):
        """Test génération de recommandations"""
        recommendations = await reporter._generate_recommendations(sample_incident, investigation_context)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Vérifier les types de recommandations
        rec_text = " ".join(recommendations).lower()
        assert "block" in rec_text  # Blocage IP
        assert "reset" in rec_text or "password" in rec_text  # Reset credentials
        assert "monitor" in rec_text or "review" in rec_text  # Monitoring
    
    @pytest.mark.asyncio
    async def test_auto_execute_actions_high_severity(self, reporter, investigation_context):
        """Test exécution automatique pour incidents haute sévérité"""
        high_severity_incident = Incident(
            type="bruteforce",
            severity="high",
            summary="Critical brute force attack",
            entities={
                "ip": "45.33.32.156",
                "user": "admin",
                "endpoint": "/login"
            }
        )
        
        actions = await reporter.auto_execute_actions(high_severity_incident)
        
        assert isinstance(actions, list)
        assert len(actions) > 0
        
        # Vérifier les types d'actions exécutées
        action_types = [action.action_type for action in actions]
        assert "block_ip" in action_types
        
        # Vérifier le succès des actions
        for action in actions:
            assert action.success is True
            assert action.target in ["45.33.32.156", "admin"]
    
    @pytest.mark.asyncio
    async def test_no_auto_actions_low_severity(self, reporter):
        """Test absence d'actions automatiques pour faible sévérité"""
        low_severity_incident = Incident(
            type="rare_ip",
            severity="low",
            summary="Rare IP detected",
            entities={"ip": "192.168.1.100"}
        )
        
        actions = await reporter.auto_execute_actions(low_severity_incident)
        
        # Pas d'actions automatiques pour faible sévérité
        assert isinstance(actions, list)
        assert len(actions) == 0
    
    @pytest.mark.asyncio
    async def test_generate_incident_batch_summary(self, reporter):
        """Test génération de résumé par batch"""
        incidents = [
            Incident(
                type="bruteforce",
                severity="high",
                summary="Brute force attack 1",
                entities={"ip": "45.33.32.156"}
            ),
            Incident(
                type="spike5xx",
                severity="medium", 
                summary="Server errors spike",
                entities={"endpoint": "/api/process"}
            ),
            Incident(
                type="bruteforce",
                severity="high",
                summary="Brute force attack 2",
                entities={"ip": "203.0.113.50"}
            )
        ]
        
        summary = await reporter.generate_incident_batch_summary(incidents)
        
        assert isinstance(summary, dict)
        assert "total_incidents" in summary
        assert "severity_breakdown" in summary
        assert "type_breakdown" in summary
        assert "key_findings" in summary
        assert "overall_risk_level" in summary
        
        # Vérifier les comptes
        assert summary["total_incidents"] == 3
        assert summary["severity_breakdown"]["high"] == 2
        assert summary["severity_breakdown"]["medium"] == 1
        assert summary["type_breakdown"]["bruteforce"] == 2
        assert summary["type_breakdown"]["spike5xx"] == 1
    
    @pytest.mark.asyncio
    async def test_create_action_plan(self, reporter, sample_incident, investigation_context):
        """Test création de plan d'action"""
        action_plan = await reporter._create_action_plan(sample_incident, investigation_context)
        
        assert isinstance(action_plan, dict)
        assert "immediate_actions" in action_plan
        assert "follow_up_actions" in action_plan
        assert "monitoring_actions" in action_plan
        
        # Vérifier les actions immédiates
        immediate = action_plan["immediate_actions"]
        assert isinstance(immediate, list)
        assert len(immediate) > 0
        
        # Devrait inclure blocage IP pour incident haute sévérité
        actions_text = " ".join(immediate).lower()
        assert "block" in actions_text
    
    def test_risk_calculation(self, reporter, investigation_context):
        """Test calcul du niveau de risque"""
        risk_level = reporter._calculate_risk_level(investigation_context)
        
        assert risk_level in ["low", "medium", "high", "critical"]
        
        # Avec le contexte fourni (IP malveillante, Tor, threat feeds), devrait être high/critical
        assert risk_level in ["high", "critical"]
    
    @pytest.mark.asyncio
    async def test_compliance_recommendations(self, reporter, sample_incident):
        """Test recommandations de conformité"""
        compliance_recs = await reporter._generate_compliance_recommendations(sample_incident)
        
        assert isinstance(compliance_recs, list)
        
        # Pour un incident de brute force, devrait inclure des recs de conformité
        if len(compliance_recs) > 0:
            recs_text = " ".join(compliance_recs).lower()
            # Peut inclure GDPR, SOX, PCI-DSS selon le contexte
            assert any(term in recs_text for term in ["gdpr", "compliance", "audit", "policy"])
    
    @pytest.mark.asyncio
    async def test_timeline_analysis(self, reporter, investigation_context):
        """Test analyse de timeline"""
        timeline_analysis = await reporter._analyze_timeline(investigation_context.timeline)
        
        assert isinstance(timeline_analysis, dict)
        assert "duration" in timeline_analysis
        assert "event_count" in timeline_analysis
        assert "attack_pattern" in timeline_analysis
        
        # Vérifier les métriques
        assert timeline_analysis["event_count"] == len(investigation_context.timeline)
        assert timeline_analysis["duration"] > 0  # En secondes
    
    @pytest.mark.asyncio
    async def test_report_error_handling(self, reporter):
        """Test gestion des erreurs dans les rapports"""
        # Incident minimal sans contexte
        minimal_incident = Incident(
            type="unknown",
            severity="low",
            summary="Test incident"
        )
        
        empty_context = InvestigationContext(
            incident_id=minimal_incident.id,
            related_logs=[]
        )
        
        # Ne devrait pas échouer même avec des données minimales
        final_incident = await reporter.generate_report(minimal_incident, empty_context)
        
        assert isinstance(final_incident, Incident)
        assert final_incident.id == minimal_incident.id
        assert len(final_incident.recommendations) >= 0  # Au moins vide, pas d'erreur

if __name__ == "__main__":
    pytest.main([__file__, "-v"])