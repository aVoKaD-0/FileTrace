import json
from typing import Dict, List
from fastapi import WebSocket

app_loop = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, analysis_id: str, websocket: WebSocket):
        await websocket.accept()
        if analysis_id not in self.active_connections:
            self.active_connections[analysis_id] = []
        self.active_connections[analysis_id].append(websocket)

    def disconnect(self, analysis_id: str, websocket: WebSocket):
        if analysis_id in self.active_connections:
            self.active_connections[analysis_id].remove(websocket)
            if not self.active_connections[analysis_id]:
                del self.active_connections[analysis_id]

    async def send_message(self, analysis_id: str, message: json):
        if analysis_id in self.active_connections:
            for connection in self.active_connections[analysis_id]:
                await connection.send_text(message)

manager = ConnectionManager() 