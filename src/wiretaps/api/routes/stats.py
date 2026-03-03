"""Statistics endpoints."""

from fastapi import APIRouter, Request

router = APIRouter(tags=["stats"])


@router.get("/stats")
async def get_stats(request: Request) -> dict:
    """Get overall event statistics."""
    storage = request.app.state.storage
    return storage.get_event_stats()


@router.get("/stats/by-day")
async def get_stats_by_day(request: Request, days: int = 7) -> list[dict]:
    """Get event statistics grouped by day."""
    storage = request.app.state.storage
    return storage.get_event_stats_by_day(days=days)


@router.get("/stats/by-type")
async def get_stats_by_type(request: Request) -> list[dict]:
    """Get event statistics grouped by type."""
    storage = request.app.state.storage
    return storage.get_event_stats_by_type()
