from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime
from uuid import uuid4

class LogEntry(BaseModel):
    timestamp: datetime
    ip: str
    user: Optional[str] = None
    endpoint: str
    status: int
    method: str = "GET"
    user_agent: Optional[str] = None
    payload_size: Optional[int] = None
    response_time: Optional[float] = None
    
class LogChunk(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    content: str
    embedding: Optional[List[float]] = None
    metadata: Dict[str, Any]
    timestamp: datetime

class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    ts: datetime = Field(default_factory=datetime.now)
    type: Literal["bruteforce", "spike5xx", "rare_ip", "suspicious_path"]
    entities: Dict[str, str] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)
    severity: Literal["low", "medium", "high"]
    summary: str
    recommendations: List[str] = Field(default_factory=list)

class DetectionRule(BaseModel):
    name: str
    description: str
    enabled: bool = True
    threshold: Dict[str, Any] = Field(default_factory=dict)

class InvestigationContext(BaseModel):
    incident_id: str
    related_logs: List[LogEntry]
    ip_intelligence: Optional[Dict[str, Any]] = None
    user_context: Optional[Dict[str, Any]] = None
    timeline: List[Dict[str, Any]] = Field(default_factory=list)

class ActionResult(BaseModel):
    action_type: str
    target: str
    success: bool
    message: str
    timestamp: datetime = Field(default_factory=datetime.now)

class ScanRequest(BaseModel):
    window_hours: int = 24
    rules: Optional[List[str]] = None

class IngestResponse(BaseModel):
    processed_count: int
    indexed_count: int
    message: str