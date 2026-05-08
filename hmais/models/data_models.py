
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class InvestigationPhase(str, Enum):
    INVESTIGATION = "Investigation"
    REFINEMENT = "Refinement"
    CONCLUSION = "Conclusion"

class SuspicionLevel(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    UNKNOWN = "Unknown"

class Plan(BaseModel):
    phase: InvestigationPhase
    thought_process: str
    next_action: str
    stop_investigation: bool = False

class QueryResult(BaseModel):
    success: bool
    count: Optional[int] = None
    data: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None

class Event(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    properties: Dict[str, Any]
    suspicion_level: SuspicionLevel = SuspicionLevel.UNKNOWN

class Judgement(BaseModel):
    is_malicious: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str

class MemoryState(BaseModel):
    attack_nodes: List[str] = Field(default_factory=list)
    attack_edges: List[tuple] = Field(default_factory=list)
    narrative_log: List[str] = Field(default_factory=list)

    def add_malicious_event(self, event: Event, judgement: Judgement, mitre_technique: str = None):
        self.attack_nodes.append(event.event_id)
        technique_str = mitre_technique if mitre_technique and mitre_technique != "N/A" else 'malicious activity'
        self.narrative_log.append(
            f"[{event.timestamp}] Identified {technique_str}: "
            f"{event.event_type} - {judgement.reasoning}"
        )

    def get_context_summary(self) -> str:
        return f"Attack Graph: {len(self.attack_nodes)} malicious nodes, {len(self.attack_edges)} edges\n" + \
               f"Recent findings: {len(self.narrative_log)} events analyzed"
