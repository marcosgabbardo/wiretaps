"""FastAPI application factory for wiretaps v2."""

from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from wiretaps import __version__
from wiretaps.api.routes import agents, events, sessions, stats
from wiretaps.storage import Storage


def create_app(storage: Storage | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="wiretaps",
        description="See what your AI agents are sending to LLMs.",
        version=__version__,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.storage = storage or Storage()

    # Health check
    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
        }

    # Mount route modules
    app.include_router(agents.router)
    app.include_router(sessions.router)
    app.include_router(events.router)
    app.include_router(stats.router)

    return app
