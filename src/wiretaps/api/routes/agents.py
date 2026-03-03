"""Agent management endpoints."""

from fastapi import APIRouter, HTTPException, Request

from wiretaps.api.schemas import AgentCreate, AgentResponse

router = APIRouter(tags=["agents"])


@router.get("/agents", response_model=list[AgentResponse])
async def list_agents(request: Request) -> list[dict]:
    """List all registered agents."""
    storage = request.app.state.storage
    agents = storage.list_agents()
    return [{"id": a.id, "name": a.name, "created_at": a.created_at} for a in agents]


@router.post("/agents", response_model=AgentResponse, status_code=201)
async def create_agent(body: AgentCreate, request: Request) -> dict:
    """Register a new agent."""
    storage = request.app.state.storage
    agent = storage.create_agent(body.name)
    return {"id": agent.id, "name": agent.name, "created_at": agent.created_at}
