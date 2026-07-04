import json
from typing import Dict, List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.active_connections:
            self.active_connections[org_id] = []
        self.active_connections[org_id].append(websocket)

    async def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.active_connections:
            try:
                self.active_connections[org_id].remove(websocket)
            except ValueError:
                pass
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]

    async def broadcast_to_org(self, message: dict, org_id: str):
        if org_id not in self.active_connections:
            return
        dead = []
        for ws in self.active_connections[org_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws, org_id)

    async def broadcast_all(self, message: dict):
        for org_id in list(self.active_connections.keys()):
            await self.broadcast_to_org(message, org_id)


manager = ConnectionManager()
