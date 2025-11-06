from typing import List, Dict, Any, Optional
from app.models import Incident, InvestigationContext
from mcp_tools.actions import actions
from langchain.schema import HumanMessage
from langchain_openai import ChatOpenAI
import json

class ReporterAgent:
    def __init__(self):
        self.llm = ChatOpenAI(temperature=0, model="gpt-4")
        self.severity_weights = {
            'bruteforce': {'base': 3, 'success_multiplier': 2},
            'spike5xx': {'base': 2, 'volume_multiplier': 1.5},
            'rare_ip': {'base': 2, 'sensitivity_multiplier': 1.8},
            'suspicious_path': {'base': 3, 'payload_multiplier': 1.5}
        }
    
    async def generate_report(self, incident: Incident, context: InvestigationContext) -> Incident:
        """Generate final incident report with severity and recommendations"""
        
        # Step 1: Assign severity
        incident.severity = await self._assign_severity(incident, context)
        
        # Step 2: Generate recommendations
        incident.recommendations = await self._generate_recommendations(incident, context)
        
        # Step 3: Enhance summary with context
        incident.summary = await self._enhance_summary(incident, context)
        
        return incident
    
    async def _assign_severity(self, incident: Incident, context: InvestigationContext) -> str:
        """Assign severity based on incident type, context, and intelligence"""
        base_score = self.severity_weights.get(incident.type, {}).get('base', 2)
        
        # Modify based on context
        multiplier = 1.0
        
        # IP intelligence factors
        if context.ip_intelligence:
            threat_score = context.ip_intelligence.get('threat_score', 0)
            if threat_score > 70:
                multiplier += 0.8
            elif threat_score > 40:
                multiplier += 0.4
            
            if context.ip_intelligence.get('reputation') == 'suspicious':
                multiplier += 0.5
        
        # User context factors
        if context.user_context:
            unique_ips = len(context.user_context.get('unique_ips', []))
            if unique_ips > 5:  # User from many IPs
                multiplier += 0.3
        
        # Related logs volume
        if len(context.related_logs) > 50:
            multiplier += 0.4
        elif len(context.related_logs) > 20:
            multiplier += 0.2
        
        # Timeline density (many events in short time)
        if len(context.timeline) > 10:
            time_span = max(1, (max(e['timestamp'] for e in context.timeline) - 
                               min(e['timestamp'] for e in context.timeline)).total_seconds() / 3600)
            if time_span < 1:  # Many events in < 1 hour
                multiplier += 0.6
        
        final_score = base_score * multiplier
        
        if final_score >= 4:
            return "high"
        elif final_score >= 2.5:
            return "medium"
        else:
            return "low"
    
    async def _generate_recommendations(self, incident: Incident, context: InvestigationContext) -> List[str]:
        """Generate actionable recommendations based on incident analysis"""
        recommendations = []
        
        # Base recommendations by incident type
        if incident.type == "bruteforce":
            recommendations.extend([
                f"Block IP address {incident.entities.get('ip', 'unknown')}",
                f"Force password reset for user {incident.entities.get('user', 'unknown')}",
                "Review authentication logs for additional compromised accounts",
                "Implement account lockout policies if not already in place",
                "Consider enabling multi-factor authentication"
            ])
        
        elif incident.type == "spike5xx":
            recommendations.extend([
                "Investigate server health and resource utilization",
                "Review application logs for underlying causes",
                "Check for potential DoS attacks or resource exhaustion",
                "Scale resources if needed to handle load",
                "Implement error monitoring and alerting"
            ])
        
        elif incident.type == "rare_ip":
            recommendations.extend([
                f"Monitor IP address {incident.entities.get('ip', 'unknown')} for continued activity",
                f"Review access logs for endpoint {incident.entities.get('endpoint', 'unknown')}",
                "Consider IP-based access restrictions for sensitive endpoints",
                "Implement geo-blocking if appropriate",
                "Enhance monitoring for unusual access patterns"
            ])
        
        elif incident.type == "suspicious_path":
            recommendations.extend([
                f"Block IP address {incident.entities.get('ip', 'unknown')} immediately",
                "Scan systems for potential compromise",
                "Review WAF rules and update attack signatures",
                "Patch applications against injection vulnerabilities",
                "Implement input validation and sanitization"
            ])
        
        # Context-based recommendations
        if context.ip_intelligence:
            threat_score = context.ip_intelligence.get('threat_score', 0)
            reputation = context.ip_intelligence.get('reputation', 'unknown')
            
            if threat_score > 50 or reputation == 'suspicious':
                recommendations.insert(0, f"High-priority: Block malicious IP {incident.entities.get('ip', 'unknown')}")
            
            if context.ip_intelligence.get('is_tor'):
                recommendations.append("Consider blocking Tor exit nodes if not needed for business")
            
            if context.ip_intelligence.get('country'):
                country = context.ip_intelligence['country']
                recommendations.append(f"Review geo-restriction policies for traffic from {country}")
        
        # User context recommendations
        if context.user_context:
            unique_ips = len(context.user_context.get('unique_ips', []))
            if unique_ips > 3:
                recommendations.append(f"User {incident.entities.get('user', 'unknown')} shows unusual IP diversity - investigate account security")
        
        # LLM-enhanced recommendations
        llm_recs = await self._llm_recommendations(incident, context)
        recommendations.extend(llm_recs)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Limit to top 10 recommendations
    
    async def _llm_recommendations(self, incident: Incident, context: InvestigationContext) -> List[str]:
        """Generate additional recommendations using LLM"""
        
        context_summary = {
            'incident_type': incident.type,
            'severity': incident.severity,
            'entities': incident.entities,
            'evidence_count': len(incident.evidence),
            'ip_reputation': context.ip_intelligence.get('reputation') if context.ip_intelligence else None,
            'related_logs_count': len(context.related_logs),
            'user_context_available': bool(context.user_context)
        }
        
        prompt = f"""As a cybersecurity expert, provide 3-5 specific, actionable recommendations for this security incident.

Incident Summary:
{json.dumps(context_summary, indent=2)}

Evidence:
{json.dumps(incident.evidence[:5], indent=2)}  # First 5 pieces of evidence

Focus on:
1. Immediate containment actions
2. Investigation steps to prevent similar incidents
3. Long-term security improvements
4. Specific technical controls to implement

Return only a JSON array of recommendation strings, no other text."""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            return json.loads(response.content)
        except Exception as e:
            print(f"LLM recommendations error: {e}")
            return ["Review incident manually for additional recommendations"]
    
    async def _enhance_summary(self, incident: Incident, context: InvestigationContext) -> str:
        """Enhance incident summary with contextual information"""
        base_summary = incident.summary
        
        enhancements = []
        
        # Add IP intelligence context
        if context.ip_intelligence:
            reputation = context.ip_intelligence.get('reputation', 'unknown')
            threat_score = context.ip_intelligence.get('threat_score', 0)
            country = context.ip_intelligence.get('country', 'unknown')
            
            if reputation != 'clean':
                enhancements.append(f"IP has {reputation} reputation (threat score: {threat_score})")
            if country != 'unknown':
                enhancements.append(f"Traffic originates from {country}")
        
        # Add user context
        if context.user_context:
            unique_ips = len(context.user_context.get('unique_ips', []))
            if unique_ips > 1:
                enhancements.append(f"User associated with {unique_ips} unique IP addresses")
        
        # Add timeline context
        if len(context.timeline) > 5:
            enhancements.append(f"Part of {len(context.timeline)} related security events")
        
        if enhancements:
            enhanced_summary = f"{base_summary}. Additional context: {'; '.join(enhancements)}."
        else:
            enhanced_summary = base_summary
        
        return enhanced_summary
    
    async def auto_execute_actions(self, incident: Incident) -> List[Dict[str, Any]]:
        """Automatically execute recommended security actions"""
        executed_actions = []
        
        # Only auto-execute for high severity incidents with clear IP targets
        if incident.severity != "high" or "ip" not in incident.entities:
            return executed_actions
        
        target_ip = incident.entities["ip"]
        
        # Auto-block for specific high-risk incident types
        auto_block_types = ["bruteforce", "suspicious_path"]
        
        if incident.type in auto_block_types:
            try:
                result = await actions.block_ip(target_ip, f"Auto-blocked due to {incident.type} incident {incident.id}")
                executed_actions.append({
                    "action": "block_ip",
                    "target": target_ip,
                    "success": result.success,
                    "message": result.message
                })
            except Exception as e:
                executed_actions.append({
                    "action": "block_ip",
                    "target": target_ip,
                    "success": False,
                    "message": f"Failed to auto-block: {e}"
                })
        
        return executed_actions
    
    async def generate_incident_batch_summary(self, incidents: List[Incident]) -> Dict[str, Any]:
        """Generate a summary report for multiple incidents"""
        if not incidents:
            return {}
        
        summary = {
            'total_incidents': len(incidents),
            'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0},
            'type_breakdown': {},
            'top_ips': {},
            'timeframe': {
                'start': min(i.ts for i in incidents),
                'end': max(i.ts for i in incidents)
            },
            'recommendations_summary': []
        }
        
        # Count by severity and type
        for incident in incidents:
            summary['severity_breakdown'][incident.severity] += 1
            summary['type_breakdown'][incident.type] = summary['type_breakdown'].get(incident.type, 0) + 1
            
            if 'ip' in incident.entities:
                ip = incident.entities['ip']
                summary['top_ips'][ip] = summary['top_ips'].get(ip, 0) + 1
        
        # Get top 5 IPs
        summary['top_ips'] = dict(sorted(summary['top_ips'].items(), key=lambda x: x[1], reverse=True)[:5])
        
        # Aggregate common recommendations
        all_recommendations = []
        for incident in incidents:
            all_recommendations.extend(incident.recommendations)
        
        from collections import Counter
        common_recs = Counter(all_recommendations).most_common(5)
        summary['recommendations_summary'] = [{'recommendation': rec, 'frequency': count} for rec, count in common_recs]
        
        return summary

reporter = ReporterAgent()