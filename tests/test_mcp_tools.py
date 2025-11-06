#!/usr/bin/env python3
"""
Tests pour les outils MCP (Model Context Protocol)
"""
import pytest
import tempfile
import os
import json
from datetime import datetime

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock aiofiles et loguru avant d'importer
class MockAiofilesOpen:
    def __init__(self, content):
        self.lines = content.split('\n') if isinstance(content, str) else content
        self.index = 0
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        pass
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self.index >= len(self.lines):
            raise StopAsyncIteration
        line = self.lines[self.index]
        self.index += 1
        return line
    
    async def read(self):
        return '\n'.join(self.lines)

def mock_aiofiles_open(file_path, mode='r'):
    # Déterminer le contenu basé sur le nom du fichier
    if 'apache' in str(file_path):
        content = '''192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"
45.33.32.156 - - [01/Jan/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"'''
    elif 'jsonl' in str(file_path):
        content = '''{"ts": "2024-01-01T12:00:00Z", "ip": "192.168.1.100", "endpoint": "/dashboard", "status": 200}
{"ts": "2024-01-01T12:05:00Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 401, "user": "admin"}'''
    else:
        content = ''
    
    return MockAiofilesOpen(content)

sys.modules['aiofiles'] = type(sys)('mock_aiofiles')
sys.modules['aiofiles'].open = mock_aiofiles_open

# Mock loguru
class MockLogger:
    def info(self, msg):
        pass
    
    def error(self, msg):
        pass
    
    def warning(self, msg):
        pass

sys.modules['loguru'] = type(sys)('mock_loguru')
sys.modules['loguru'].logger = MockLogger()

from mcp_tools.logs import LogsReader
from mcp_tools.actions import SecurityActions
from app.models import LogEntry, ActionResult

class TestLogsReader:
    
    @pytest.fixture
    def logs_reader(self):
        """Créer une instance du lecteur de logs"""
        return LogsReader()
    
    def create_apache_log_file(self):
        """Créer un fichier de log Apache temporaire"""
        content = '''192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"
192.168.1.101 - - [01/Jan/2024:10:01:00 +0000] "POST /api/users HTTP/1.1" 200 512 "-" "Mozilla/5.0"
45.33.32.156 - admin [01/Jan/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "AttackBot/1.0"'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(content)
            return f.name
    
    def create_jsonl_log_file(self):
        """Créer un fichier de log JSONL temporaire"""
        logs = [
            {"ts": "2024-01-01T12:00:00Z", "ip": "192.168.1.100", "endpoint": "/dashboard", "status": 200, "method": "GET"},
            {"ts": "2024-01-01T12:05:00Z", "ip": "45.33.32.156", "endpoint": "/login", "status": 401, "method": "POST", "user": "admin"},
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
            return f.name
    
    @pytest.mark.asyncio
    async def test_parse_apache_logs(self, logs_reader):
        """Test de parsing des logs Apache"""
        # Utilise le mock qui retourne du contenu Apache
        file_path = "test_apache.log"
        
        # Mock Path.exists pour retourner True
        original_exists = Path.exists
        Path.exists = lambda self: True
        
        try:
            logs = await logs_reader.read(file_path)
            
            assert len(logs) == 2, f"Expected 2 logs, got {len(logs)}"
            
            # Vérifier le premier log
            log1 = logs[0]
            assert isinstance(log1, LogEntry)
            assert log1.ip == "192.168.1.100"
            assert log1.endpoint == "/index.html"
            assert log1.status == 200
            assert log1.method == "GET"
            assert log1.user_agent == "Mozilla/5.0"
            
            # Vérifier le deuxième log
            log2 = logs[1]
            assert log2.ip == "45.33.32.156"
            assert log2.endpoint == "/login"
            assert log2.status == 401
            assert log2.method == "POST"
            assert log2.user_agent == "AttackBot/1.0"
        
        finally:
            Path.exists = original_exists
    
    @pytest.mark.asyncio
    async def test_parse_jsonl_logs(self, logs_reader):
        """Test de parsing des logs JSONL"""
        file_path = "test_logs.jsonl"
        
        # Mock Path.exists pour retourner True
        original_exists = Path.exists
        Path.exists = lambda self: True
        
        try:
            logs = await logs_reader.read(file_path)
            
            assert len(logs) == 2, f"Expected 2 logs, got {len(logs)}"
            
            # Vérifier le premier log
            log1 = logs[0]
            assert isinstance(log1, LogEntry)
            assert log1.ip == "192.168.1.100"
            assert log1.endpoint == "/dashboard"
            assert log1.status == 200
            
            # Vérifier le deuxième log
            log2 = logs[1]
            assert log2.ip == "45.33.32.156"
            assert log2.endpoint == "/login"
            assert log2.status == 401
            assert log2.user == "admin"
        
        finally:
            Path.exists = original_exists
    
    @pytest.mark.asyncio
    async def test_file_not_found(self, logs_reader):
        """Test de gestion d'un fichier inexistant"""
        with pytest.raises(FileNotFoundError):
            await logs_reader.read("nonexistent.log")
    
    def test_parse_timestamp_formats(self, logs_reader):
        """Test de parsing des différents formats de timestamp"""
        # Format Apache
        ts1 = logs_reader._parse_timestamp("01/Jan/2024:10:00:00")
        assert isinstance(ts1, datetime)
        assert ts1.year == 2024
        assert ts1.month == 1
        assert ts1.day == 1
        
        # Format ISO
        ts2 = logs_reader._parse_timestamp("2024-01-01T12:00:00Z")
        assert isinstance(ts2, datetime)
        assert ts2.year == 2024
        
        # Format invalide - devrait retourner datetime.now()
        ts3 = logs_reader._parse_timestamp("invalid-format")
        assert isinstance(ts3, datetime)
    
    def test_parse_json_log(self, logs_reader):
        """Test de parsing d'un log JSON individuel"""
        log_data = {
            "ts": "2024-01-01T12:00:00Z",
            "ip": "192.168.1.100",
            "endpoint": "/api/test",
            "status": 200,
            "method": "POST",
            "user": "testuser",
            "ua": "TestAgent/1.0"
        }
        
        log_entry = logs_reader._parse_json_log(log_data)
        
        assert isinstance(log_entry, LogEntry)
        assert log_entry.ip == "192.168.1.100"
        assert log_entry.endpoint == "/api/test"
        assert log_entry.status == 200
        assert log_entry.method == "POST"
        assert log_entry.user == "testuser"
        assert log_entry.user_agent == "TestAgent/1.0"
    
    def test_parse_json_log_flexible_keys(self, logs_reader):
        """Test de parsing JSON avec des clés alternatives"""
        log_data = {
            "timestamp": "2024-01-01T12:00:00Z",  # Clé alternative pour ts
            "client_ip": "192.168.1.200",         # Clé alternative pour ip
            "url": "/api/data",                   # Clé alternative pour endpoint
            "response_code": 404,                 # Clé alternative pour status
            "username": "alice"                   # Clé alternative pour user
        }
        
        log_entry = logs_reader._parse_json_log(log_data)
        
        assert log_entry.ip == "192.168.1.200"
        assert log_entry.endpoint == "/api/data"
        assert log_entry.status == 404
        assert log_entry.user == "alice"

class TestSecurityActions:
    
    @pytest.fixture
    def security_actions(self):
        """Créer une instance des actions de sécurité"""
        return SecurityActions()
    
    @pytest.mark.asyncio
    async def test_block_ip_success(self, security_actions):
        """Test de blocage d'IP réussi"""
        ip = "45.33.32.156"
        reason = "Brute force attack detected"
        
        result = await security_actions.block_ip(ip, reason)
        
        assert isinstance(result, ActionResult)
        assert result.action_type == "block_ip"
        assert result.target == ip
        assert result.success is True
        assert ip in result.message
        assert reason in result.message
        
        # Vérifier que l'IP est bien bloquée
        assert ip in security_actions.blocked_ips
        
        # Vérifier que l'action est loggée
        assert len(security_actions.action_log) == 1
        assert security_actions.action_log[0].action_type == "block_ip"
    
    @pytest.mark.asyncio
    async def test_unblock_ip_success(self, security_actions):
        """Test de déblocage d'IP réussi"""
        ip = "45.33.32.156"
        
        # D'abord bloquer l'IP
        await security_actions.block_ip(ip, "Test block")
        assert ip in security_actions.blocked_ips
        
        # Puis la débloquer
        result = await security_actions.unblock_ip(ip)
        
        assert isinstance(result, ActionResult)
        assert result.action_type == "unblock_ip"
        assert result.target == ip
        assert result.success is True
        
        # Vérifier que l'IP n'est plus bloquée
        assert ip not in security_actions.blocked_ips
        
        # Vérifier que l'action est loggée
        assert len(security_actions.action_log) == 2  # block + unblock
    
    @pytest.mark.asyncio
    async def test_rate_limit_ip_success(self, security_actions):
        """Test de limitation de taux d'IP"""
        ip = "192.168.1.100"
        limit = 10
        
        result = await security_actions.rate_limit_ip(ip, limit)
        
        assert isinstance(result, ActionResult)
        assert result.action_type == "rate_limit"
        assert result.target == ip
        assert result.success is True
        assert str(limit) in result.message
        
        # Vérifier que la limite est enregistrée
        assert ip in security_actions.rate_limits
        # La limite peut être stockée dans une structure avec plus d'info
        rate_limit_data = security_actions.rate_limits[ip]
        if isinstance(rate_limit_data, dict):
            assert rate_limit_data['limit'] == limit
        else:
            assert rate_limit_data == limit
    
    @pytest.mark.asyncio
    async def test_reset_tokens_success(self, security_actions):
        """Test de réinitialisation de tokens"""
        user = "testuser"
        
        result = await security_actions.reset_tokens(user)
        
        assert isinstance(result, ActionResult)
        assert result.action_type == "reset_tokens"
        assert result.target == user
        assert result.success is True
        assert user in result.message
    
    def test_get_blocked_ips(self, security_actions):
        """Test de récupération des IPs bloquées"""
        # Initialement aucune IP bloquée
        blocked = security_actions.get_blocked_ips()
        assert isinstance(blocked, list)
        assert len(blocked) == 0
        
        # Bloquer quelques IPs
        security_actions.blocked_ips.add("192.168.1.100")
        security_actions.blocked_ips.add("45.33.32.156")
        
        blocked = security_actions.get_blocked_ips()
        assert len(blocked) == 2
        assert "192.168.1.100" in blocked
        assert "45.33.32.156" in blocked
    
    def test_get_action_history(self, security_actions):
        """Test de récupération de l'historique des actions"""
        # Initialement aucune action
        history = security_actions.get_action_history()
        assert isinstance(history, list)
        assert len(history) == 0
        
        # Ajouter une action manuellement pour le test
        test_action = ActionResult(
            action_type="test_action",
            target="test_target",
            success=True,
            message="Test action"
        )
        security_actions.action_log.append(test_action)
        
        history = security_actions.get_action_history()
        assert len(history) == 1
        assert history[0].action_type == "test_action"
        assert history[0].target == "test_target"
        assert history[0].success is True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])