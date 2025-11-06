from fastapi import FastAPI, HTTPException, File, UploadFile, Depends, Query, Request
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import List, Optional, Dict, Any
import json
import sqlite3
from datetime import datetime, timedelta
import tempfile
import os
from pathlib import Path
import traceback

from app.models import (
    Incident, ScanRequest, IngestResponse, 
    ActionResult, DetectionRule
)
from agents.graph import security_graph
from mcp_tools.actions import actions
from storage import init_storage

app = FastAPI(
    title="AI Security Log Analyzer",
    description="AI-powered security log analysis and incident detection system",
    version="1.0.0"
)

# Custom error handlers - return errors as JSON only
@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Return all HTTP errors as JSON"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": str(exc.detail),
                "type": "http_error",
                "timestamp": datetime.now().isoformat()
            }
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Return all unhandled errors as JSON"""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error",
                "type": "server_error",
                "details": str(exc) if app.debug else "An unexpected error occurred",
                "timestamp": datetime.now().isoformat()
            }
        }
    )

@app.on_event("startup")
async def startup_event():
    """Initialize storage on startup"""
    init_storage()
    print("AI Security Log Analyzer started")

@app.post("/ingest", response_model=IngestResponse)
async def ingest_logs(file: UploadFile = File(...)):
    """
    Ingest log files (.log or .jsonl)
    Parse, embed, and store in vector database
    """
    if not file.filename.endswith(('.log', '.jsonl')):
        raise HTTPException(
            status_code=400, 
            detail={
                "message": "Only .log and .jsonl files are supported",
                "allowed_formats": [".log", ".jsonl"],
                "received_format": Path(file.filename).suffix
            }
        )
    
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        # Process through the graph
        result = await security_graph.process_logs(tmp_file_path)
        
        # Clean up temp file
        os.unlink(tmp_file_path)
        
        metadata = result.get("metadata", {})
        
        return IngestResponse(
            processed_count=metadata.get("ingested_count", 0),
            indexed_count=metadata.get("indexed_count", 0),
            message=f"Successfully processed {file.filename}"
        )
        
    except Exception as e:
        # Clean up temp file if it exists
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.unlink(tmp_file_path)
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error processing file",
                "filename": file.filename,
                "error": str(e)
            }
        )

@app.post("/scan")
async def scan_logs(request: ScanRequest):
    """
    Scan logs within time window and detect anomalies
    Run detection rules and return incidents
    """
    try:
        incidents = await security_graph.scan_recent_logs(request.window_hours)
        
        # Filter by requested rules if specified
        if request.rules:
            incidents = [i for i in incidents if i.type in request.rules]
        
        return {
            "incidents": [incident.dict() for incident in incidents],
            "scan_window_hours": request.window_hours,
            "total_incidents": len(incidents),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error during scan",
                "window_hours": request.window_hours,
                "error": str(e)
            }
        )

@app.get("/incidents", response_model=List[Dict[str, Any]])
async def get_incidents(
    severity: Optional[str] = Query(None, regex="^(low|medium|high)$"),
    incident_type: Optional[str] = Query(None, regex="^(bruteforce|spike5xx|rare_ip|suspicious_path)$"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Get incidents with optional filtering
    """
    try:
        conn = sqlite3.connect("storage/db.sqlite")
        
        # Build query with filters
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if incident_type:
            query += " AND type = ?"
            params.append(incident_type)
        
        query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        
        incidents = []
        for row in rows:
            incident_data = {
                "id": row[0],           # id
                "ts": row[1],           # ts
                "type": row[2],         # type
                "entities": {           # reconstruct entities from ip, user, endpoint
                    "ip": row[3] or "",
                    "user": row[4] or "",
                    "endpoint": row[5] or ""
                },
                "severity": row[6],     # severity
                "summary": row[7],      # summary
                "recommendations": json.loads(row[8]) if row[8] else [],  # recs (JSON)
                "evidence": json.loads(row[9]) if row[9] else [],        # evidence (JSON)
                "created_at": row[10]   # created_at
            }
            incidents.append(incident_data)
        
        conn.close()
        return incidents
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error retrieving incidents",
                "filters": {"severity": severity, "type": incident_type},
                "error": str(e)
            }
        )

@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """
    Get specific incident by ID
    """
    try:
        conn = sqlite3.connect("storage/db.sqlite")
        cursor = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(
                status_code=404, 
                detail={
                    "message": "Incident not found",
                    "incident_id": incident_id
                }
            )
        
        return {
            "id": row[0],           # id
            "ts": row[1],           # ts
            "type": row[2],         # type
            "entities": {           # reconstruct entities from ip, user, endpoint
                "ip": row[3] or "",
                "user": row[4] or "",
                "endpoint": row[5] or ""
            },
            "severity": row[6],     # severity
            "summary": row[7],      # summary
            "recommendations": json.loads(row[8]) if row[8] else [],  # recs (JSON)
            "evidence": json.loads(row[9]) if row[9] else [],        # evidence (JSON)
            "created_at": row[10]   # created_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error retrieving incident",
                "incident_id": incident_id,
                "error": str(e)
            }
        )

@app.post("/actions/block-ip", response_model=ActionResult)
async def block_ip(ip: str, reason: Optional[str] = "Manual block"):
    """
    Block an IP address
    """
    try:
        result = await actions.block_ip(ip, reason)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error blocking IP",
                "ip": ip,
                "reason": reason,
                "error": str(e)
            }
        )

@app.post("/actions/unblock-ip", response_model=ActionResult)
async def unblock_ip(ip: str):
    """
    Unblock an IP address
    """
    try:
        result = await actions.unblock_ip(ip)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error unblocking IP",
                "ip": ip,
                "error": str(e)
            }
        )

@app.post("/actions/rate-limit-ip", response_model=ActionResult)
async def rate_limit_ip(ip: str, requests_per_minute: int = 10):
    """
    Apply rate limiting to an IP address
    """
    try:
        result = await actions.rate_limit_ip(ip, requests_per_minute)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error applying rate limit",
                "ip": ip,
                "requests_per_minute": requests_per_minute,
                "error": str(e)
            }
        )

@app.post("/actions/reset-tokens", response_model=ActionResult)
async def reset_user_tokens(user: str):
    """
    Reset authentication tokens for a user
    """
    try:
        result = await actions.reset_tokens(user)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error resetting tokens",
                "user": user,
                "error": str(e)
            }
        )

@app.get("/actions/blocked-ips")
async def get_blocked_ips():
    """
    Get list of currently blocked IPs
    """
    try:
        blocked_ips = actions.get_blocked_ips()
        return {
            "blocked_ips": blocked_ips,
            "count": len(blocked_ips),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error retrieving blocked IPs",
                "error": str(e)
            }
        )

@app.get("/actions/history")
async def get_action_history():
    """
    Get history of security actions
    """
    try:
        history = actions.get_action_history()
        return {
            "actions": [action.dict() for action in history],
            "count": len(history)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error retrieving action history",
                "error": str(e)
            }
        )

@app.get("/stats")
async def get_stats():
    """
    Get system statistics and health
    """
    try:
        conn = sqlite3.connect("storage/db.sqlite")
        
        # Count incidents by severity
        cursor = conn.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
        severity_counts = dict(cursor.fetchall())
        
        # Count incidents by type
        cursor = conn.execute("SELECT type, COUNT(*) FROM incidents GROUP BY type")
        type_counts = dict(cursor.fetchall())
        
        # Recent incidents (last 24 hours)
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor = conn.execute("SELECT COUNT(*) FROM incidents WHERE ts > ?", (yesterday,))
        recent_incidents = cursor.fetchone()[0]
        
        # Total incidents
        cursor = conn.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
        
        conn.close()
        
        # Knowledge base stats
        from mcp_tools.kb import get_kb
        kb = get_kb()
        total_chunks = kb.get_total_chunks()
        
        return {
            "incidents": {
                "total": total_incidents,
                "recent_24h": recent_incidents,
                "by_severity": severity_counts,
                "by_type": type_counts
            },
            "knowledge_base": {
                "total_chunks": total_chunks
            },
            "security_actions": {
                "blocked_ips": len(actions.get_blocked_ips()),
                "total_actions": len(actions.get_action_history())
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error retrieving stats",
                "error": str(e)
            }
        )

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)