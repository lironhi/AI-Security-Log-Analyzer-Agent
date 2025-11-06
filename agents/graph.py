from typing import List, Dict, Any, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from app.models import LogEntry, Incident, LogChunk, InvestigationContext
from agents.detector import detector
from agents.investigator import investigator
from agents.reporter import reporter
from mcp_tools.kb import get_kb
from mcp_tools.logs import logs_reader
import json
from datetime import datetime
import sqlite3

class SecurityAnalysisState(TypedDict):
    logs: List[LogEntry]
    chunks: List[LogChunk] 
    incidents: List[Incident]
    investigation_contexts: List[InvestigationContext]
    final_incidents: List[Incident]
    metadata: Dict[str, Any]

class SecurityAnalysisGraph:
    def __init__(self):
        self.kb = get_kb()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(SecurityAnalysisState)
        
        # Add nodes
        workflow.add_node("ingest_logs", self._ingest_logs)
        workflow.add_node("chunk_and_embed", self._chunk_and_embed)
        workflow.add_node("detect_anomalies", self._detect_anomalies)
        workflow.add_node("investigate_incidents", self._investigate_incidents)
        workflow.add_node("generate_reports", self._generate_reports)
        workflow.add_node("save_incidents", self._save_incidents)
        
        # Add edges
        workflow.add_edge(START, "ingest_logs")
        workflow.add_edge("ingest_logs", "chunk_and_embed")
        workflow.add_edge("chunk_and_embed", "detect_anomalies")
        workflow.add_edge("detect_anomalies", "investigate_incidents")
        workflow.add_edge("investigate_incidents", "generate_reports")
        workflow.add_edge("generate_reports", "save_incidents")
        workflow.add_edge("save_incidents", END)
        
        return workflow.compile()
    
    async def _ingest_logs(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Ingest and parse log files"""
        print("🔍 Ingesting logs...")
        
        log_path = state.get("metadata", {}).get("log_path")
        if not log_path:
            state["logs"] = []
            return state
        
        try:
            logs = await logs_reader.read(log_path)
            state["logs"] = logs
            state["metadata"]["ingested_count"] = len(logs)
            print(f"✅ Ingested {len(logs)} log entries")
        except Exception as e:
            print(f"❌ Error ingesting logs: {e}")
            state["logs"] = []
            state["metadata"]["ingest_error"] = str(e)
        
        return state
    
    async def _chunk_and_embed(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Chunk logs and create embeddings"""
        print("📄 Chunking and embedding logs...")
        
        logs = state.get("logs", [])
        if not logs:
            state["chunks"] = []
            return state
        
        chunks = []
        
        # Create chunks from log entries with 1500 chars and 200 overlap
        chunk_size = self.kb.chunk_size
        chunk_overlap = self.kb.chunk_overlap
        
        # Combine logs into larger chunks for better context
        current_chunk = ""
        for log in logs:
            log_content = f"""
Timestamp: {log.timestamp.isoformat()}
IP: {log.ip}
Method: {log.method}
Endpoint: {log.endpoint}
Status: {log.status}
User: {log.user or 'none'}
User-Agent: {log.user_agent or 'none'}
Payload Size: {log.payload_size or 'none'}
Response Time: {log.response_time or 'none'}
---
""".strip()
            
            if len(current_chunk) + len(log_content) > chunk_size:
                # Save current chunk
                if current_chunk:
                    chunk = LogChunk(
                        content=current_chunk,
                        metadata=self._extract_chunk_metadata(current_chunk),
                        timestamp=log.timestamp
                    )
                    chunks.append(chunk)
                
                # Start new chunk with overlap
                if len(current_chunk) > chunk_overlap:
                    current_chunk = current_chunk[-chunk_overlap:] + "\n" + log_content
                else:
                    current_chunk = log_content
            else:
                current_chunk += "\n" + log_content
        
        # Add final chunk
        if current_chunk:
            chunk = LogChunk(
                content=current_chunk,
                metadata=self._extract_chunk_metadata(current_chunk),
                timestamp=logs[-1].timestamp if logs else datetime.now()
            )
            chunks.append(chunk)
        
        # Store in knowledge base
        try:
            indexed_count = await self.kb.upsert(chunks)
            state["chunks"] = chunks
            state["metadata"]["indexed_count"] = indexed_count
            print(f"✅ Indexed {indexed_count} chunks")
        except Exception as e:
            print(f"❌ Error indexing chunks: {e}")
            state["chunks"] = []
            state["metadata"]["index_error"] = str(e)
        
        return state
    
    async def _detect_anomalies(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Detect security anomalies in logs"""
        print("🚨 Detecting anomalies...")
        
        logs = state.get("logs", [])
        window_hours = state.get("metadata", {}).get("window_hours", 24)
        
        if not logs:
            state["incidents"] = []
            return state
        
        try:
            incidents = await detector.scan_window(logs, window_hours)
            state["incidents"] = incidents
            state["metadata"]["detected_incidents"] = len(incidents)
            
            print(f"✅ Detected {len(incidents)} potential incidents")
            for incident in incidents[:3]:  # Show first 3
                print(f"   - {incident.type}: {incident.summary[:100]}...")
                
        except Exception as e:
            print(f"❌ Error detecting anomalies: {e}")
            state["incidents"] = []
            state["metadata"]["detection_error"] = str(e)
        
        return state
    
    async def _investigate_incidents(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Investigate detected incidents"""
        print("🔬 Investigating incidents...")
        
        incidents = state.get("incidents", [])
        if not incidents:
            state["investigation_contexts"] = []
            return state
        
        contexts = []
        
        try:
            for incident in incidents:
                print(f"   Investigating {incident.type} incident {incident.id[:8]}...")
                context = await investigator.investigate(incident)
                contexts.append(context)
            
            state["investigation_contexts"] = contexts
            state["metadata"]["investigated_count"] = len(contexts)
            print(f"✅ Investigated {len(contexts)} incidents")
            
        except Exception as e:
            print(f"❌ Error investigating incidents: {e}")
            state["investigation_contexts"] = []
            state["metadata"]["investigation_error"] = str(e)
        
        return state
    
    async def _generate_reports(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Generate final incident reports"""
        print("📋 Generating reports...")
        
        incidents = state.get("incidents", [])
        contexts = state.get("investigation_contexts", [])
        
        if not incidents or not contexts:
            state["final_incidents"] = []
            return state
        
        final_incidents = []
        
        try:
            for incident, context in zip(incidents, contexts):
                print(f"   Generating report for {incident.type} incident...")
                final_incident = await reporter.generate_report(incident, context)
                final_incidents.append(final_incident)
                
                # Execute auto-actions for high-severity incidents
                if final_incident.severity == "high":
                    auto_actions = await reporter.auto_execute_actions(final_incident)
                    if auto_actions:
                        print(f"   Executed {len(auto_actions)} automatic actions")
            
            state["final_incidents"] = final_incidents
            state["metadata"]["final_report_count"] = len(final_incidents)
            
            # Generate batch summary
            batch_summary = await reporter.generate_incident_batch_summary(final_incidents)
            state["metadata"]["batch_summary"] = batch_summary
            
            print(f"✅ Generated {len(final_incidents)} final reports")
            
        except Exception as e:
            print(f"❌ Error generating reports: {e}")
            state["final_incidents"] = []
            state["metadata"]["reporting_error"] = str(e)
        
        return state
    
    async def _save_incidents(self, state: SecurityAnalysisState) -> SecurityAnalysisState:
        """Save incidents to database"""
        print("💾 Saving incidents to database...")
        
        incidents = state.get("final_incidents", [])
        if not incidents:
            return state
        
        try:
            conn = sqlite3.connect("storage/db.sqlite")
            saved_count = 0
            
            for incident in incidents:
                conn.execute("""
                    INSERT OR REPLACE INTO incidents 
                    (id, ts, type, ip, user, endpoint, severity, summary, recs, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident.id,
                    incident.ts.isoformat(),
                    incident.type,
                    incident.entities.get('ip'),
                    incident.entities.get('user'),
                    incident.entities.get('endpoint'),
                    incident.severity,
                    incident.summary,
                    json.dumps(incident.recommendations),
                    json.dumps(incident.evidence)
                ))
                saved_count += 1
            
            conn.commit()
            conn.close()
            
            state["metadata"]["saved_count"] = saved_count
            print(f"✅ Saved {saved_count} incidents to database")
            
        except Exception as e:
            print(f"❌ Error saving incidents: {e}")
            state["metadata"]["save_error"] = str(e)
        
        return state
    
    async def process_logs(self, log_path: str, window_hours: int = 24) -> Dict[str, Any]:
        """Process logs through the complete analysis pipeline"""
        print("🚀 Starting security log analysis pipeline...")
        
        initial_state = SecurityAnalysisState(
            logs=[],
            chunks=[],
            incidents=[],
            investigation_contexts=[],
            final_incidents=[],
            metadata={
                "log_path": log_path,
                "window_hours": window_hours,
                "started_at": datetime.now().isoformat()
            }
        )
        
        try:
            result = await self.graph.ainvoke(initial_state)
            
            # Add completion metadata
            result["metadata"]["completed_at"] = datetime.now().isoformat()
            result["metadata"]["status"] = "success"
            
            print("✅ Analysis pipeline completed successfully!")
            
            return {
                "incidents": [incident.dict() for incident in result.get("final_incidents", [])],
                "metadata": result.get("metadata", {}),
                "summary": result.get("metadata", {}).get("batch_summary", {})
            }
            
        except Exception as e:
            print(f"❌ Pipeline failed: {e}")
            return {
                "incidents": [],
                "metadata": {"status": "error", "error": str(e)},
                "summary": {}
            }
    
    def _extract_chunk_metadata(self, chunk_content: str) -> Dict[str, Any]:
        """Extract metadata from chunk content"""
        metadata = {}
        lines = chunk_content.split('\n')
        
        # Extract first and last IPs for chunk metadata
        ips = []
        for line in lines:
            if line.startswith('IP: '):
                ip = line.replace('IP: ', '').strip()
                if ip and ip != 'none':
                    ips.append(ip)
        
        if ips:
            metadata['ips'] = list(set(ips))
            metadata['primary_ip'] = ips[0]
        
        return metadata
    
    async def scan_recent_logs(self, window_hours: int = 24) -> List[Incident]:
        """Scan recently indexed logs for new incidents"""
        print(f"🔍 Scanning recent logs (last {window_hours} hours)...")
        
        # This would typically query logs from the knowledge base
        # For now, return empty list as we need actual log data
        return []

# Global graph instance
security_graph = SecurityAnalysisGraph()