# AI Security Log Analyzer Agent

An AI-powered security log analysis system for anomaly detection and automated incident response.

## 🎯 Description and Objective

**AI Security Log Analyzer Agent** is an intelligent cybersecurity tool that uses multi-specialized AI agents to analyze server logs and automatically detect security threats.

### Main Objectives:
- **Automatic detection** of security attacks (brute force, scans, anomalies)
- **Intelligent analysis** with event correlation and IP intelligence
- **Automated response** with IP blocking and security actions
- **Modern API interface** for integration into existing infrastructure

### Specialized AI Agents:
- **🔍 Detector Agent**: Identifies brute force attacks, 5xx error spikes, suspicious IPs
- **🔬 Investigator Agent**: Correlates events and enriches with IP intelligence  
- **📋 Reporter Agent**: Generates detailed reports and executes security actions

## 🚀 How to Use

### Installation and Configuration

1. **Clone the project**
```bash
git clone <repository-url>
cd AI-Security-Log-Analyzer-Agent
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configuration (.env)**
```env
OPENAI_API_KEY=your_openai_api_key_here
REDIS_ENABLED=false  # or true if Redis available
FAISS_INDEX_PATH=storage/faiss_index
SQLITE_PATH=storage/db.sqlite
LOG_LEVEL=INFO
```

4. **Initialize the system**
```bash
python main.py init
```

5. **Start the server**
```bash
python main.py server
```

The API will be available at http://localhost:8000 with documentation at /docs

### CLI Usage

**Analyze logs directly:**
```bash
python main.py process /path/to/access.log --window 24
```

### API Usage

**Ingest logs:**
```bash
curl -X POST "http://localhost:8000/ingest" -F "file=@access.log"
```

**Scan for incidents:**
```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"window_hours": 24}'
```

**Security actions:**
```bash
curl -X POST "http://localhost:8000/actions/block-ip" \
     -H "Content-Type: application/json" \
     -d '{"ip": "192.168.1.100", "reason": "Brute force attack"}'
```

## 🧪 Testing

### Running Tests

The project includes a comprehensive test suite covering all components:

**Run all tests:**
```bash
python -m pytest tests/ -v
```

**Run specific test categories:**
```bash
# Test data models
python -m pytest tests/test_models.py -v

# Test API endpoints  
python -m pytest tests/test_api.py -v

# Test detector agent
python -m pytest tests/test_detector_agent.py -v

# Test cache system
python -m pytest tests/test_cache.py -v
```

**Test coverage:**
```bash
python -m pytest tests/ --cov=app --cov=agents --cov=mcp_tools
```

### Test Structure

- **test_models.py**: Data model validation (17 tests)
- **test_api.py**: FastAPI endpoints and integration (15 tests)  
- **test_detector_agent.py**: Anomaly detection logic (10 tests)
- **test_cache.py**: Redis/memory cache functionality (12 tests)
- **test_storage.py**: Database operations and schema
- **test_investigator.py**: Investigation agent and IP intelligence
- **test_reporter.py**: Report generation and security actions
- **test_graph_integration.py**: Complete workflow testing

### Running Specific Tests

**Test with verbose output:**
```bash
python -m pytest tests/test_detector_agent.py::TestDetectorAgent::test_bruteforce_detection -v
```

**Test with short traceback:**
```bash
python -m pytest tests/ -v --tb=short
```

**Test in parallel:**
```bash
python -m pytest tests/ -n auto
```

## 📚 Usage Examples

### 🔐 Scenario 1: Daily Monitoring

**Situation:** Daily monitoring of an e-commerce web server

```bash
# Automatic analysis of the last 24h logs
python main.py process /var/log/nginx/access.log --window 24

# Via API for automation
curl -X POST "http://localhost:8000/ingest" -F "file=@/var/log/nginx/access.log"
curl -X POST "http://localhost:8000/scan" -d '{"window_hours": 24}' -H "Content-Type: application/json"
```

**Typical Results:**
- 🚨 **Brute force detected**: IP 45.134.89.12 - 150 attempts on /admin/login
- ⚠️ **5xx error spike**: 80 500 errors between 2-3pm (server overload)
- 🔍 **Suspicious IP**: 192.168.1.100 accessing /wp-admin (WordPress not installed)

### 🛡️ Scenario 2: Post-Deployment Monitoring

**Situation:** Monitoring the first hours after deploying a new API

```bash
# Real-time monitoring every hour
while true; do
    python main.py process /var/log/api/access.log --window 1
    sleep 3600
done
```

**Automatic Actions:**
- IP blocked automatically if >100 requests/min
- Rate limiting applied to sensitive endpoints  
- Alerts sent for new vulnerabilities

### 🏢 Scenario 3: Monthly Security Audit

**Situation:** Monthly audit to identify attack trends

```bash
# Analyze all logs from the month
python main.py process /var/log/archive/access-2024-08-*.log --window 720

# Export incidents for reporting
curl "http://localhost:8000/incidents" | jq '.' > security_audit_august.json
```

**Analysis Report:**
```json
{
  "incidents": [
    {
      "type": "bruteforce",
      "ip": "203.0.113.42", 
      "summary": "142 failed connection attempts on /admin",
      "severity": "high",
      "recommendations": [
        "Implement CAPTCHA after 3 failures",
        "Block IP for 24h"
      ]
    }
  ],
  "stats": {
    "total_requests": 2847392,
    "unique_ips": 18274,
    "incidents_high": 3,
    "incidents_medium": 12
  }
}
```

### 🚀 Scenario 4: Monitoring Integration

**Situation:** Integrate AI analysis into your monitoring stack (Grafana/ELK)

```python
#!/usr/bin/env python3
import requests

def check_security_incidents():
    # Scan for incidents
    response = requests.post(
        "http://localhost:8000/scan",
        json={"window_hours": 1}
    )
    
    incidents = response.json()["incidents"]
    
    # Send critical incidents to Slack/Teams
    for incident in incidents:
        if incident["severity"] == "high":
            send_alert_to_slack(incident)
            
    return {
        "incidents_count": len(incidents),
        "high_severity": sum(1 for i in incidents if i["severity"] == "high")
    }

# Run every 15 minutes via cron
# */15 * * * * /path/to/check_security_incidents.py
```

### 🔧 Scenario 5: Automated Response

**Situation:** Automatically block malicious IPs and notify the team

```bash
# Automated response script
incidents=$(curl -s -X POST "http://localhost:8000/scan" -d '{"window_hours": 1}' -H "Content-Type: application/json")

# Actions for critical incidents
echo "$incidents" | jq -r '.incidents[] | select(.severity=="high") | .entities.ip' | while read ip; do
    # Block in firewall
    curl -X POST "http://localhost:8000/actions/block-ip" \
         -d "{\"ip\":\"$ip\", \"reason\":\"Auto-blocked: high severity incident\"}" \
         -H "Content-Type: application/json"
    
    # Notify team
    echo "IP $ip automatically blocked" | slack-notify
done
```

## 🔍 Detected Incident Types

- **Brute Force**: Repeated connection attempts
- **5xx Spikes**: Abnormal server error peaks
- **Rare IPs**: Geographically suspicious IP addresses
- **Suspicious Paths**: Access to dangerous endpoints (/admin, /wp-admin, etc.)

## 📊 Supported Log Formats

**Apache/Nginx:**
```
192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```

**JSON:**
```json
{"timestamp": "2023-01-01T12:00:00Z", "ip": "192.168.1.1", "method": "GET", "path": "/api/login", "status": 401}
```

## 🏗️ Architecture

```
app/
  api.py          # FastAPI endpoints
  models.py       # Pydantic data models
  cache.py        # Redis/Memory cache layer
agents/
  detector.py     # Anomaly detection agent
  investigator.py # Correlation and investigation agent
  reporter.py     # Reporting and action agent
  graph.py        # LangGraph orchestration
mcp_tools/
  logs.py         # Log parsing and ingestion
  kb.py           # Knowledge base (FAISS)
  intel.py        # IP intelligence
  actions.py      # Security actions
storage/
  __init__.py     # Database initialization
tests/
  test_*.py       # Comprehensive test suite
main.py           # CLI entry point
```

## 🔧 Development

### Adding New Tests

```bash
# Create a new test file
touch tests/test_new_feature.py

# Follow the existing patterns
class TestNewFeature:
    def test_something(self):
        assert True
```

### Test Configuration

The project uses `pytest.ini` for test configuration:
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
```

---

**AI Security Log Analyzer Agent** - Secure your infrastructure with artificial intelligence 🛡️