"""Real-time event dispatcher and WebSocket manager for Sh4d0w_St4lk3r.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Provides WebSocket connection management and event broadcasting for:
- alert.created
- alert.updated
- alert.status_changed
- case.created
- case.updated
- case.status_changed
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.realtime.manager import ConnectionManager, manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Real-Time WebSockets"])


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """WebSocket endpoint streaming live security alerts, cases, and risk events."""
    await manager.connect(websocket)
    try:
        # Keep connection open and handle incoming ping/pong or client queries
        while True:
            data = await websocket.receive_text()
            # Respond to ping
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket exception: %s", e)
        manager.disconnect(websocket)
