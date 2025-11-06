from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from app.models import Incident, InvestigationContext, LogEntry
from mcp_tools.kb import get_kb
from mcp_tools.intel import intel_provider
from langchain.schema import HumanMessage
from langchain_openai import ChatOpenAI
import json

class InvestigatorAgent:
    def __init__(self):
        self.llm = ChatOpenAI(temperature=0, model="gpt-4")
        self.kb = get_kb()
    
    async def investigate(self, incident: Incident) -> InvestigationContext:
        """Investigate an incident by gathering context and correlating data"""
        context = InvestigationContext(incident_id=incident.id, related_logs=[])
        
        # Step 1: Gather related logs using vector search
        await self._gather_related_logs(incident, context)
        
        # Step 2: Get IP intelligence if available
        if 'ip' in incident.entities:
            context.ip_intelligence = await intel_provider.ip(incident.entities['ip'])
        
        # Step 3: Correlate user activity if available
        if 'user' in incident.entities:
            await self._correlate_user_activity(incident.entities['user'], context)
        
        # Step 4: Build timeline
        await self._build_timeline(incident, context)
        
        # Step 5: Use LLM for additional analysis
        await self._llm_analysis(incident, context)
        
        return context
    
    async def _gather_related_logs(self, incident: Incident, context: InvestigationContext):
        """Use FAISS to find related log entries"""
        search_queries = []
        
        # Create search queries based on incident type and entities
        if incident.type == "bruteforce":
            search_queries.extend([
                f"IP {incident.entities.get('ip', '')} authentication login",
                f"user {incident.entities.get('user', '')} failed login",
                f"brute force attack {incident.entities.get('ip', '')}"
            ])
        elif incident.type == "spike5xx":
            search_queries.extend([
                "server error 5xx",
                "internal server error",
                "service unavailable"
            ])
        elif incident.type == "rare_ip":
            search_queries.extend([
                f"IP {incident.entities.get('ip', '')} access",
                f"endpoint {incident.entities.get('endpoint', '')}",
                "unauthorized access attempt"
            ])
        elif incident.type == "suspicious_path":
            search_queries.extend([
                f"IP {incident.entities.get('ip', '')} suspicious",
                f"endpoint {incident.entities.get('endpoint', '')}",
                "attack payload injection"
            ])
        
        # Search and collect related logs
        all_results = []
        for query in search_queries:
            if query.strip():
                results = await self.kb.search(query, k=10)
                all_results.extend(results)
        
        # Convert search results back to LogEntry objects (simplified)
        # In a real implementation, you'd properly deserialize the metadata
        for result in all_results[:20]:  # Limit to prevent overload
            metadata = result.get('metadata', {})
            if 'ip' in metadata:
                log_entry = LogEntry(
                    timestamp=datetime.fromisoformat(result['timestamp']),
                    ip=metadata.get('ip', ''),
                    user=metadata.get('user'),
                    endpoint=metadata.get('endpoint', ''),
                    status=metadata.get('status', 200),
                    method=metadata.get('method', 'GET'),
                    user_agent=metadata.get('user_agent'),
                    payload_size=metadata.get('payload_size'),
                    response_time=metadata.get('response_time')
                )
                context.related_logs.append(log_entry)
    
    async def _correlate_user_activity(self, user: str, context: InvestigationContext):
        """Correlate user activity patterns"""
        if not user or user == "unknown":
            return
        
        # Search for user-related logs
        user_results = await self.kb.search(f"user {user} activity", k=15)
        
        user_context = {
            'username': user,
            'total_sessions': len(user_results),
            'unique_ips': set(),
            'endpoints_accessed': set(),
            'time_pattern': [],
            'suspicious_activity': []
        }
        
        for result in user_results:
            metadata = result.get('metadata', {})
            if 'ip' in metadata:
                user_context['unique_ips'].add(metadata['ip'])
            if 'endpoint' in metadata:
                user_context['endpoints_accessed'].add(metadata['endpoint'])
            if 'timestamp' in result:
                timestamp = datetime.fromisoformat(result['timestamp'])
                user_context['time_pattern'].append(timestamp.hour)
        
        # Convert sets to lists for JSON serialization
        user_context['unique_ips'] = list(user_context['unique_ips'])
        user_context['endpoints_accessed'] = list(user_context['endpoints_accessed'])
        
        context.user_context = user_context
    
    async def _build_timeline(self, incident: Incident, context: InvestigationContext):
        """Build a chronological timeline of events"""
        timeline_events = []
        
        # Add incident timestamp
        timeline_events.append({
            'timestamp': incident.ts,
            'event_type': 'incident_detected',
            'description': f"{incident.type} incident detected",
            'details': incident.summary
        })
        
        # Add related log events
        for log in context.related_logs:
            timeline_events.append({
                'timestamp': log.timestamp,
                'event_type': 'log_entry',
                'description': f"{log.method} {log.endpoint} from {log.ip}",
                'details': f"Status: {log.status}, User: {log.user or 'none'}"
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        context.timeline = timeline_events
    
    async def _llm_analysis(self, incident: Incident, context: InvestigationContext):
        """Use LLM for deeper incident analysis"""
        
        # Prepare context summary
        context_summary = {
            'incident': {
                'type': incident.type,
                'entities': incident.entities,
                'evidence': incident.evidence,
                'summary': incident.summary
            },
            'ip_intelligence': context.ip_intelligence,
            'user_context': context.user_context,
            'related_logs_count': len(context.related_logs),
            'timeline_events': len(context.timeline)
        }
        
        prompt = f"""As a security analyst, analyze this incident and its context to provide additional insights:

Incident Context:
{json.dumps(context_summary, indent=2, default=str)}

Recent Related Log Entries (last 10):
{self._format_logs_for_llm(context.related_logs[-10:])}

Please provide:
1. Additional evidence or patterns you notice
2. Potential attack vectors or techniques used
3. Risk assessment and potential impact
4. Connections between events in the timeline
5. Any indicators of compromise (IoCs) to watch for

Respond in JSON format with keys: additional_evidence, attack_vectors, risk_assessment, event_connections, iocs"""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            analysis = json.loads(response.content)
            
            # Add LLM analysis to incident evidence
            if 'additional_evidence' in analysis:
                incident.evidence.extend(analysis['additional_evidence'])
            
            # Store full analysis in context metadata
            context.metadata = {'llm_analysis': analysis}
            
        except Exception as e:
            print(f"LLM analysis error: {e}")
            context.metadata = {'llm_analysis_error': str(e)}
    
    def _format_logs_for_llm(self, logs: List[LogEntry]) -> str:
        """Format logs for LLM analysis"""
        formatted = []
        for log in logs:
            formatted.append(
                f"{log.timestamp.isoformat()} | {log.ip} | {log.method} {log.endpoint} | "
                f"Status: {log.status} | User: {log.user or 'none'} | "
                f"UA: {(log.user_agent or 'none')[:50]}"
            )
        return '\n'.join(formatted)
    
    async def correlate_incidents(self, incidents: List[Incident]) -> Dict[str, Any]:
        """Correlate multiple incidents to find patterns"""
        if not incidents:
            return {}
        
        correlations = {
            'ip_clusters': {},
            'time_clusters': [],
            'attack_campaigns': [],
            'common_patterns': []
        }
        
        # Group by IP
        ip_groups = {}
        for incident in incidents:
            ip = incident.entities.get('ip', 'unknown')
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(incident)
        
        # Find IP clusters with multiple incidents
        for ip, ip_incidents in ip_groups.items():
            if len(ip_incidents) > 1:
                correlations['ip_clusters'][ip] = {
                    'incident_count': len(ip_incidents),
                    'incident_types': [i.type for i in ip_incidents],
                    'time_span': (
                        min(i.ts for i in ip_incidents),
                        max(i.ts for i in ip_incidents)
                    )
                }
        
        # Time-based clustering (incidents within 1 hour)
        incidents_by_time = sorted(incidents, key=lambda x: x.ts)
        for i, incident in enumerate(incidents_by_time):
            cluster = [incident]
            for j in range(i + 1, len(incidents_by_time)):
                other = incidents_by_time[j]
                if (other.ts - incident.ts).total_seconds() <= 3600:  # 1 hour
                    cluster.append(other)
                else:
                    break
            
            if len(cluster) > 1:
                correlations['time_clusters'].append({
                    'timeframe': f"{cluster[0].ts} to {cluster[-1].ts}",
                    'incidents': len(cluster),
                    'types': [i.type for i in cluster]
                })
        
        return correlations

investigator = InvestigatorAgent()