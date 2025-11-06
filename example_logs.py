#!/usr/bin/env python3
"""
Generate example log files for testing the AI Security Log Analyzer
"""
import json
from datetime import datetime, timedelta
import random

def generate_nginx_logs():
    """Generate example nginx access logs with security incidents"""
    
    # Normal IPs
    normal_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5"]
    
    # Malicious IPs
    malicious_ips = ["45.33.32.156", "185.220.100.240", "1.2.3.4"]
    
    # Endpoints
    normal_endpoints = ["/", "/home", "/api/users", "/api/products", "/login", "/about"]
    sensitive_endpoints = ["/admin", "/api/admin", "/config", "/backup"]
    attack_endpoints = [
        "/admin/../../etc/passwd",
        "/api/users?id=1' OR '1'='1",
        "/login?user=admin&password=<script>alert('xss')</script>",
        "/api/admin/../../../windows/system32/cmd.exe"
    ]
    
    # User agents
    normal_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]
    suspicious_agents = ["", "-", "sqlmap/1.6.2", "Nikto/2.1.6"]
    
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    
    # Generate normal traffic
    for i in range(200):
        timestamp = base_time + timedelta(minutes=random.randint(1, 1440))
        ip = random.choice(normal_ips)
        endpoint = random.choice(normal_endpoints)
        status = random.choices([200, 301, 404], weights=[0.8, 0.1, 0.1])[0]
        method = random.choice(["GET", "POST"])
        user = random.choice(["alice", "bob", "charlie", "-"])
        agent = random.choice(normal_agents)
        size = random.randint(200, 5000)
        
        log_line = f'{ip} - {user} [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {endpoint} HTTP/1.1" {status} {size} "{agent}"'
        logs.append((timestamp, log_line))
    
    # Generate brute force attack
    attacker_ip = random.choice(malicious_ips)
    attack_start = base_time + timedelta(hours=random.randint(1, 20))
    
    # Failed attempts
    for i in range(15):
        timestamp = attack_start + timedelta(minutes=i * 2)
        log_line = f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 401 401 "Mozilla/5.0"'
        logs.append((timestamp, log_line))
    
    # Successful attempt
    success_time = attack_start + timedelta(minutes=30)
    log_line = f'{attacker_ip} - admin [{success_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 200 2048 "Mozilla/5.0"'
    logs.append((success_time, log_line))
    
    # Generate 5xx error spike
    error_start = base_time + timedelta(hours=random.randint(5, 15))
    for i in range(25):
        timestamp = error_start + timedelta(minutes=random.randint(0, 30))
        ip = random.choice(normal_ips)
        endpoint = random.choice(normal_endpoints)
        status = random.choice([500, 502, 503])
        log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {status} 0 "Mozilla/5.0"'
        logs.append((timestamp, log_line))
    
    # Generate suspicious path attacks
    for attacker_ip in malicious_ips[:2]:
        attack_time = base_time + timedelta(hours=random.randint(8, 20))
        for endpoint in attack_endpoints:
            timestamp = attack_time + timedelta(minutes=random.randint(0, 10))
            agent = random.choice(suspicious_agents + normal_agents)
            status = random.choice([400, 403, 500])
            size = random.randint(50, 15000)
            
            log_line = f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {status} {size} "{agent}"'
            logs.append((timestamp, log_line))
    
    # Generate rare IP accessing sensitive endpoints
    rare_ip = "203.0.113.50"
    rare_time = base_time + timedelta(hours=random.randint(10, 18))
    for endpoint in sensitive_endpoints:
        timestamp = rare_time + timedelta(minutes=random.randint(0, 5))
        status = random.choice([200, 403])
        log_line = f'{rare_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {status} 1024 "Mozilla/5.0"'
        logs.append((timestamp, log_line))
    
    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])
    
    return [log[1] for log in logs]

def generate_jsonl_logs():
    """Generate example JSONL format logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=12)
    
    # Sample log entries with security incidents
    log_entries = [
        # Normal traffic
        {"ip": "192.168.1.100", "user": "john", "endpoint": "/api/users", "status": 200, "method": "GET"},
        {"ip": "192.168.1.101", "user": "jane", "endpoint": "/dashboard", "status": 200, "method": "GET"},
        
        # Brute force sequence
        {"ip": "45.33.32.156", "user": None, "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"},
        {"ip": "45.33.32.156", "user": None, "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"},
        {"ip": "45.33.32.156", "user": None, "endpoint": "/login", "status": 401, "method": "POST", "user_agent": "AttackBot/1.0"},
        {"ip": "45.33.32.156", "user": "admin", "endpoint": "/login", "status": 200, "method": "POST", "user_agent": "AttackBot/1.0"},
        
        # Suspicious paths
        {"ip": "185.220.100.240", "user": None, "endpoint": "/admin/../../etc/passwd", "status": 403, "method": "GET", "user_agent": ""},
        {"ip": "185.220.100.240", "user": None, "endpoint": "/api/users?id=1' OR '1'='1", "status": 400, "method": "GET", "payload_size": 50},
        
        # 5xx errors
        {"ip": "192.168.1.50", "user": "service", "endpoint": "/api/process", "status": 500, "method": "POST"},
        {"ip": "192.168.1.51", "user": "batch", "endpoint": "/api/batch", "status": 503, "method": "POST"},
    ]
    
    for i, entry in enumerate(log_entries):
        timestamp = base_time + timedelta(minutes=i * 10)
        entry["timestamp"] = timestamp.isoformat()
        logs.append(json.dumps(entry))
    
    return logs

def save_example_logs():
    """Save example log files"""
    
    # Generate and save nginx format logs
    nginx_logs = generate_nginx_logs()
    with open("example_access.log", "w") as f:
        f.write("\n".join(nginx_logs))
    
    print(f"✅ Generated example_access.log with {len(nginx_logs)} entries")
    
    # Generate and save JSONL format logs
    jsonl_logs = generate_jsonl_logs()
    with open("example_security.jsonl", "w") as f:
        f.write("\n".join(jsonl_logs))
    
    print(f"✅ Generated example_security.jsonl with {len(jsonl_logs)} entries")
    
    print("\n📋 To test the system:")
    print("1. python main.py init")
    print("2. python main.py process example_access.log")
    print("3. python main.py server --reload")
    print("4. Open http://localhost:8000/docs to test the API")

if __name__ == "__main__":
    save_example_logs()