from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from app.models import LogEntry, Incident
import json
from langchain.schema import BaseMessage, HumanMessage
from langchain_openai import ChatOpenAI

class DetectorAgent:
    def __init__(self):
        self.llm = ChatOpenAI(temperature=0, model="gpt-4")
        self.time_window_minutes = 5
        self.thresholds = {
            'bruteforce': {'fail_count': 5, 'time_window_minutes': 2},
            'spike5xx': {'ratio_threshold': 0.2},
            'rare_ip': {'unseen_days': 30, 'sensitive_endpoints': ['/admin', '/auth', '/login', '/token']},
            'suspicious': {'path_indicators': ['..'], 'query_length': 512, 'rate_limit': 30}
        }
        self.detection_rules = {
            'bruteforce': self._detect_bruteforce,
            'spike5xx': self._detect_spike5xx,
            'rare_ip': self._detect_rare_ip,
            'suspicious_path': self._detect_suspicious_path
        }
    
    async def scan_window(self, logs: List[LogEntry], window_hours: int = 24) -> List[Incident]:
        """Scan logs within a time window for anomalies"""
        cutoff_time = datetime.now() - timedelta(hours=window_hours)
        recent_logs = [log for log in logs if log.timestamp >= cutoff_time]
        
        incidents = []
        
        for rule_name, rule_func in self.detection_rules.items():
            rule_incidents = await rule_func(recent_logs)
            incidents.extend(rule_incidents)
        
        return incidents
    
    async def _detect_bruteforce(self, logs: List[LogEntry]) -> List[Incident]:
        """Detect brute force attacks: fail>=5 in 2m then success"""
        incidents = []
        ip_attempts = defaultdict(list)
        fail_threshold = self.thresholds['bruteforce']['fail_count']
        time_window = self.thresholds['bruteforce']['time_window_minutes']
        
        # Group by IP
        for log in logs:
            ip_attempts[log.ip].append(log)
        
        for ip, ip_logs in ip_attempts.items():
            # Sort by timestamp
            ip_logs.sort(key=lambda x: x.timestamp)
            
            for i, log in enumerate(ip_logs):
                if log.status in [200, 302]:  # Successful login
                    # Look back for failures in the time window
                    window_start = log.timestamp - timedelta(minutes=time_window)
                    failures_in_window = 0
                    
                    for j in range(i-1, -1, -1):
                        prev_log = ip_logs[j]
                        if prev_log.timestamp < window_start:
                            break
                        if prev_log.status in [401, 403]:
                            failures_in_window += 1
                    
                    if failures_in_window >= fail_threshold:
                        evidence = [
                            f"IP {ip} had {failures_in_window} failed attempts in {time_window} minutes",
                            f"Successful login at {log.timestamp}",
                            f"User: {log.user or 'unknown'}",
                            f"Endpoint: {log.endpoint}"
                        ]
                        
                        incidents.append(Incident(
                            type="bruteforce",
                            entities={"ip": ip, "user": log.user or "unknown", "endpoint": log.endpoint},
                            evidence=evidence,
                            severity="high",
                            summary=f"Brute force attack: {failures_in_window} failures then success from {ip}"
                        ))
        
        return incidents
    
    async def _detect_spike5xx(self, logs: List[LogEntry]) -> List[Incident]:
        """Detect 5xx spike: ratio>=0.2 per endpoint/window"""
        incidents = []
        ratio_threshold = self.thresholds['spike5xx']['ratio_threshold']
        window_minutes = self.time_window_minutes
        
        # Group by endpoint and time window
        endpoint_windows = defaultdict(lambda: defaultdict(lambda: {'total': 0, 'errors': 0}))
        
        for log in logs:
            # Create time window (5-minute buckets)
            window_start = log.timestamp.replace(second=0, microsecond=0)
            window_start = window_start.replace(minute=(window_start.minute // window_minutes) * window_minutes)
            
            endpoint_windows[log.endpoint][window_start]['total'] += 1
            if 500 <= log.status <= 599:
                endpoint_windows[log.endpoint][window_start]['errors'] += 1
        
        for endpoint, time_windows in endpoint_windows.items():
            for window_time, counts in time_windows.items():
                if counts['total'] >= 5:  # Minimum requests threshold
                    error_rate = counts['errors'] / counts['total']
                    
                    if error_rate >= ratio_threshold:
                        evidence = [
                            f"5xx error rate: {error_rate:.2%} ({counts['errors']}/{counts['total']})",
                            f"Endpoint: {endpoint}",
                            f"Time window: {window_time} ({window_minutes}min)",
                            f"Threshold exceeded: {ratio_threshold:.2%}"
                        ]
                        
                        incidents.append(Incident(
                            type="spike5xx",
                            entities={"endpoint": endpoint, "time_window": str(window_time)},
                            evidence=evidence,
                            severity="medium",
                            summary=f"5xx error spike on {endpoint}: {error_rate:.2%} error rate"
                        ))
        
        return incidents
    
    async def _detect_rare_ip(self, logs: List[LogEntry]) -> List[Incident]:
        """Detect rare_ip if unseen in last 30d hitting /admin|/auth|/login|/token"""
        incidents = []
        sensitive_endpoints = self.thresholds['rare_ip']['sensitive_endpoints']
        unseen_days = self.thresholds['rare_ip']['unseen_days']
        
        # For this implementation, we'll consider IPs that appear very infrequently
        # In production, this would check against historical data from the last 30 days
        ip_counts = Counter(log.ip for log in logs)
        cutoff_time = datetime.now() - timedelta(days=unseen_days)
        
        seen_rare_ips = set()
        for log in logs:
            # Check if accessing sensitive endpoints
            if any(endpoint in log.endpoint for endpoint in sensitive_endpoints):
                # Consider IP rare if it has very few requests (≤2 in current window)
                # In production, this would query historical data
                if ip_counts[log.ip] <= 2 and log.ip not in seen_rare_ips:
                    seen_rare_ips.add(log.ip)
                    
                    evidence = [
                        f"Rare IP {log.ip} accessing sensitive endpoint {log.endpoint}",
                        f"IP appears only {ip_counts[log.ip]} times in current window",
                        f"Endpoint matches sensitive pattern: {[e for e in sensitive_endpoints if e in log.endpoint]}",
                        f"Timestamp: {log.timestamp}"
                    ]
                    
                    incidents.append(Incident(
                        type="rare_ip",
                        entities={"ip": log.ip, "endpoint": log.endpoint, "user": log.user or "unknown"},
                        evidence=evidence,
                        severity="medium",
                        summary=f"Rare IP {log.ip} accessed sensitive endpoint {log.endpoint}"
                    ))
        
        return incidents
    
    async def _detect_suspicious_path(self, logs: List[LogEntry]) -> List[Incident]:
        """Detect suspicious if path contains .. or qlen>512 or ua empty or >30 req/min"""
        incidents = []
        path_indicators = self.thresholds['suspicious']['path_indicators']
        query_length_limit = self.thresholds['suspicious']['query_length']
        rate_limit = self.thresholds['suspicious']['rate_limit']
        
        # Track request rates per IP per minute
        ip_request_rates = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            minute_window = log.timestamp.replace(second=0, microsecond=0)
            ip_request_rates[log.ip][minute_window] += 1
        
        for log in logs:
            endpoint = log.endpoint
            user_agent = log.user_agent or ''
            suspicious_found = []
            
            # Check for path traversal indicators
            for indicator in path_indicators:
                if indicator in endpoint:
                    suspicious_found.append(f"path_traversal_{indicator}")
            
            # Check query string length
            if '?' in endpoint:
                query_string = endpoint.split('?', 1)[1]
                if len(query_string) > query_length_limit:
                    suspicious_found.append(f"long_query_{len(query_string)}")
            
            # Check for empty user agent
            if not user_agent or user_agent.strip() in ['-', '']:
                suspicious_found.append("empty_user_agent")
            
            # Check request rate for this IP
            minute_window = log.timestamp.replace(second=0, microsecond=0)
            requests_per_minute = ip_request_rates[log.ip][minute_window]
            if requests_per_minute > rate_limit:
                suspicious_found.append(f"high_rate_{requests_per_minute}_req_per_min")
            
            if suspicious_found:
                evidence = [
                    f"Suspicious indicators: {', '.join(suspicious_found)}",
                    f"Endpoint: {endpoint}",
                    f"IP: {log.ip}",
                    f"User-Agent: {user_agent or 'empty'}",
                    f"Timestamp: {log.timestamp}",
                    f"Request rate: {requests_per_minute} req/min"
                ]
                
                incidents.append(Incident(
                    type="suspicious_path",
                    entities={"ip": log.ip, "endpoint": endpoint, "user": log.user or "unknown"},
                    evidence=evidence,
                    severity="high",
                    summary=f"Suspicious activity from {log.ip}: {', '.join(suspicious_found)}"
                ))
        
        return incidents
    
    async def analyze_with_llm(self, logs: List[LogEntry]) -> List[Dict[str, Any]]:
        """Use LLM to analyze logs for potential incidents"""
        log_summary = self._create_log_summary(logs[:50])  # Limit for token efficiency
        
        prompt = f"""Given these security logs, analyze for potential security incidents and output candidate incidents in JSON format.

Log Summary:
{log_summary}

Rules to detect:
1. Brute force: Many failed logins (401/403) then success (200/302) from same IP
2. 5xx spike: High ratio of server errors in short time
3. Rare IP: Infrequent IPs accessing sensitive endpoints (/admin, /api, /auth, etc.)
4. Suspicious paths: Directory traversal (../), injection attempts, XSS, empty user agents, large payloads

For each incident found, output JSON with:
- type: "bruteforce|spike5xx|rare_ip|suspicious_path"
- entities: {{"ip": "", "user": "", "endpoint": ""}}
- evidence: ["detail1", "detail2"]
- summary: "brief description"

Output only valid JSON array of incidents, no other text."""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            return json.loads(response.content)
        except Exception as e:
            print(f"LLM analysis error: {e}")
            return []
    
    def _create_log_summary(self, logs: List[LogEntry]) -> str:
        """Create a concise summary of logs for LLM analysis"""
        summary_lines = []
        for log in logs:
            summary_lines.append(
                f"{log.timestamp.isoformat()} {log.ip} {log.method} {log.endpoint} "
                f"{log.status} user:{log.user or 'none'} ua:{log.user_agent[:50] if log.user_agent else 'none'}"
            )
        return '\n'.join(summary_lines)

detector = DetectorAgent()