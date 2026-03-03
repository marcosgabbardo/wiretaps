"""Pydantic models for API request/response validation."""

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class AgentResponse(BaseModel):
    id: str
    name: str
    created_at: str


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class SessionCreate(BaseModel):
    agent_id: str
    pid: int | None = None
    metadata: dict | None = None


class SessionUpdate(BaseModel):
    ended_at: str | None = None


class SessionResponse(BaseModel):
    id: str
    agent_id: str
    started_at: str
    ended_at: str | None = None
    pid: int | None = None
    metadata: dict | None = None


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


class EventIngest(BaseModel):
    session_id: str
    type: str = Field(..., pattern=r"^(llm_call|shell_cmd|http_request)$")
    timestamp: str
    duration_ms: int = 0
    data: dict = Field(default_factory=dict)
    pii_types: list[str] = Field(default_factory=list)
    status: int = 0
    error: str | None = None


class EventResponse(BaseModel):
    id: int
    session_id: str
    type: str
    timestamp: str
    duration_ms: int
    data: dict
    pii_types: list[str]
    status: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class StatsResponse(BaseModel):
    total_events: int
    total_tokens: int
    events_with_pii: int
    pii_percentage: float
    errors: int
    by_type: dict[str, int]


class StatsByDayItem(BaseModel):
    day: str
    events: int
    pii_detections: int
    llm_calls: int
    shell_cmds: int
    http_requests: int


class StatsByTypeItem(BaseModel):
    type: str
    count: int
    avg_duration_ms: float
    pii_detections: int
    errors: int


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------


class PaginatedResponse(BaseModel):
    count: int
    offset: int
    limit: int
