"""Real-time WebSocket connection manager and event dispatcher for Sh4d0w_St4lk3r.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

This module holds the singleton ConnectionManager instance independently of any
FastAPI router or endpoint definitions to prevent circular import loops between
backend.alerts and backend.api packages.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections for live UI and SOC broadcasting."""

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._history: List[Dict[str, Any]] = []
        self._max_history = 100

    async def connect(self, websocket: WebSocket) -> None:
        """Accept connection and register client."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove disconnected client."""
        self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    def clear_history(self) -> None:
        """Clear cached event history so reconnecting clients do not receive stale events."""
        self._history.clear()
        logger.info("WebSocket event history cleared.")

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast payload to all connected clients."""
        payload = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Store in event history
        self._history.append(payload)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        serialized = json.dumps(payload, default=str)
        dead_connections: List[WebSocket] = []

        for connection in list(self.active_connections):
            try:
                await connection.send_text(serialized)
            except Exception as e:
                logger.debug("Failed to send WebSocket message: %s", e)
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    def dispatch(self, event_type: str, data: Dict[str, Any]) -> None:
        """Synchronous dispatcher that schedules broadcast on active event loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(event_type, data))
        except RuntimeError:
            # If no running loop (e.g., sync CLI/unit test runner), log and store in history
            payload = {
                "type": event_type,
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._history.append(payload)
            if len(self._history) > self._max_history:
                self._history.pop(0)


# Global singleton instance
manager = ConnectionManager()
