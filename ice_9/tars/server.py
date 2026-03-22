"""TARS agent server — WebSocket REPL + REST API.

Run with:
    python -m ice_9.tars.server
    uvicorn ice_9.tars.server:app --host 0.0.0.0 --port 8444
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ice_9.tars.bootstrap import build_agent
from ice_9.ai.agent_loop import AgentLoop, TaskResult

app = FastAPI(
    title="TARS Agent Server",
    description="Tactical Autonomous Reasoning System — WebSocket REPL and REST API",
    version="0.1.0",
)


# ------------------------------------------------------------------
# Startup / shutdown
# ------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    app.state.agent = build_agent()


@app.on_event("shutdown")
async def shutdown() -> None:
    agent: AgentLoop = app.state.agent
    agent.memory.close()
    agent.llm.close()


# ------------------------------------------------------------------
# REST endpoints
# ------------------------------------------------------------------

class TaskRequest(BaseModel):
    prompt: str
    context: str = ""


class TaskResponse(BaseModel):
    answer: str
    success: bool
    iterations: int
    duration_ms: float
    steps: list[dict[str, Any]]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "operational", "system": "TARS"}


@app.post("/api/task", response_model=TaskResponse)
async def run_task(req: TaskRequest) -> TaskResponse:
    """One-shot task execution."""
    agent: AgentLoop = app.state.agent
    loop = asyncio.get_event_loop()
    result: TaskResult = await loop.run_in_executor(
        None, agent.run, req.prompt, req.context,
    )
    return TaskResponse(
        answer=result.final_answer,
        success=result.success,
        iterations=result.iterations,
        duration_ms=result.total_duration_ms,
        steps=[
            {
                "type": s.type.value,
                "content": s.content[:500],
                "tool": s.tool_name,
                "tool_result": s.tool_result[:500] if s.tool_result else "",
                "model": s.model_used,
                "provider": s.provider_used,
            }
            for s in result.steps
        ],
    )


@app.get("/api/memory/stats")
async def memory_stats() -> dict[str, Any]:
    """Return memory subsystem statistics."""
    agent: AgentLoop = app.state.agent
    stats: dict[str, Any] = {
        "working_memory": {
            "messages": len(agent.memory.working.messages),
            "has_summary": bool(agent.memory.working.running_summary),
            "token_estimate": agent.memory.working.token_estimate,
        },
        "episodic_memory": {
            "total_episodes": agent.memory.episodic.count(),
        },
    }
    if agent.memory.rag is not None:
        stats["rag"] = {"total_chunks": agent.memory.rag.count()}
    return stats


# ------------------------------------------------------------------
# WebSocket REPL
# ------------------------------------------------------------------

@app.websocket("/ws/chat")
async def websocket_chat(ws: WebSocket) -> None:
    """Interactive TARS REPL over WebSocket.

    Send a JSON message: {"prompt": "...", "context": "..."}
    Receive a JSON response with the full TaskResult.
    """
    await ws.accept()
    agent: AgentLoop = app.state.agent
    loop = asyncio.get_event_loop()

    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
                prompt = data.get("prompt", raw)
                context = data.get("context", "")
            except json.JSONDecodeError:
                prompt = raw
                context = ""

            result: TaskResult = await loop.run_in_executor(
                None, agent.run, prompt, context,
            )

            await ws.send_json(
                {
                    "answer": result.final_answer,
                    "success": result.success,
                    "iterations": result.iterations,
                    "duration_ms": result.total_duration_ms,
                    "steps": [
                        {
                            "type": s.type.value,
                            "content": s.content[:500],
                            "tool": s.tool_name,
                            "model": s.model_used,
                        }
                        for s in result.steps
                    ],
                }
            )
    except WebSocketDisconnect:
        pass


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main() -> None:
    """Run the TARS server."""
    import uvicorn

    uvicorn.run(
        "ice_9.tars.server:app",
        host="0.0.0.0",
        port=8444,
        log_level="info",
    )


if __name__ == "__main__":
    main()
