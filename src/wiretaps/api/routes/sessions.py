"""Session management endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request

from wiretaps.api.schemas import SessionCreate, SessionResponse, SessionUpdate

router = APIRouter(tags=["sessions"])


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    request: Request,
    agent_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List sessions with optional agent filter."""
    storage = request.app.state.storage
    sessions = storage.list_sessions(agent_id=agent_id, limit=limit, offset=offset)
    return [
        {
            "id": s.id,
            "agent_id": s.agent_id,
            "started_at": s.started_at,
            "ended_at": s.ended_at,
            "pid": s.pid,
            "metadata": s.metadata,
        }
        for s in sessions
    ]


@router.post("/sessions", response_model=SessionResponse, status_code=201)
async def create_session(body: SessionCreate, request: Request) -> dict:
    """Create a new monitoring session."""
    storage = request.app.state.storage
    agent = storage.get_agent(body.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    session = storage.create_session(
        agent_id=body.agent_id,
        pid=body.pid,
        metadata=body.metadata,
    )
    return {
        "id": session.id,
        "agent_id": session.agent_id,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "pid": session.pid,
        "metadata": session.metadata,
    }


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str, request: Request) -> dict:
    """Get session details."""
    storage = request.app.state.storage
    session = storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "id": session.id,
        "agent_id": session.agent_id,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "pid": session.pid,
        "metadata": session.metadata,
    }


@router.patch("/sessions/{session_id}", response_model=SessionResponse)
async def update_session(
    session_id: str, body: SessionUpdate, request: Request
) -> dict:
    """Update session (e.g. mark ended)."""
    storage = request.app.state.storage
    session = storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if body.ended_at is not None:
        storage.update_session(session_id, ended_at=body.ended_at)
    updated = storage.get_session(session_id)
    return {
        "id": updated.id,
        "agent_id": updated.agent_id,
        "started_at": updated.started_at,
        "ended_at": updated.ended_at,
        "pid": updated.pid,
        "metadata": updated.metadata,
    }


@router.get("/sessions/{session_id}/events")
async def list_session_events(
    session_id: str,
    request: Request,
    type: str | None = None,
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List events for a specific session."""
    storage = request.app.state.storage
    session = storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    events = storage.list_events(
        session_id=session_id, event_type=type, limit=limit, offset=offset
    )
    return {
        "events": [
            {
                "id": e.id,
                "session_id": e.session_id,
                "type": e.type,
                "timestamp": e.timestamp,
                "duration_ms": e.duration_ms,
                "data": e.data,
                "pii_types": e.pii_types,
                "status": e.status,
                "error": e.error,
            }
            for e in events
        ],
        "count": len(events),
        "offset": offset,
        "limit": limit,
    }
