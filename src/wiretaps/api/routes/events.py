"""Event endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request

from wiretaps.api.schemas import EventIngest, EventResponse
from wiretaps.storage import Event

router = APIRouter(tags=["events"])


@router.get("/events")
async def list_events(
    request: Request,
    type: str | None = None,
    session_id: str | None = None,
    pii_only: bool = False,
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List events with filters."""
    storage = request.app.state.storage
    events = storage.list_events(
        session_id=session_id,
        event_type=type,
        pii_only=pii_only,
        limit=limit,
        offset=offset,
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


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: int, request: Request) -> dict:
    """Get event details by ID."""
    storage = request.app.state.storage
    event = storage.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return {
        "id": event.id,
        "session_id": event.session_id,
        "type": event.type,
        "timestamp": event.timestamp,
        "duration_ms": event.duration_ms,
        "data": event.data,
        "pii_types": event.pii_types,
        "status": event.status,
        "error": event.error,
    }


@router.post("/events/ingest", status_code=201)
async def ingest_event(body: EventIngest, request: Request) -> dict:
    """Ingest an event from sitecustomize or external sources."""
    storage = request.app.state.storage
    session = storage.get_session(body.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    event = Event(
        session_id=body.session_id,
        type=body.type,
        timestamp=body.timestamp,
        duration_ms=body.duration_ms,
        data=body.data,
        pii_types=body.pii_types,
        status=body.status,
        error=body.error,
    )
    event_id = storage.insert_event(event)
    return {"id": event_id, "status": "ok"}
