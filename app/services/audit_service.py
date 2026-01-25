from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request
from app.repositories.audit_repository import AuditRepository
from app.core.crypto import encrypt_str, encrypt_ip
from app.core.logging import REQUEST_ID_CTX


class AuditService:
    def __init__(self, db: AsyncSession):
        self.repo = AuditRepository(db)

    async def log(self, *, request: Optional[Request], event_type: str, user_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        ip = None
        ua = None
        rid = None
        try:
            if request is not None:
                ip = request.headers.get("x-forwarded-for", request.client.host if request.client else None)
                ua = request.headers.get("user-agent")
                rid = request.headers.get("x-request-id")
        except Exception:
            pass

        if not rid:
            try:
                rid = REQUEST_ID_CTX.get()
            except Exception:
                rid = None
        safe_metadata = self._sanitize_metadata(metadata or {})
        await self.repo.create(
            event_type=event_type,
            user_id=user_id,
            source_ip=encrypt_ip(ip),
            user_agent=ua,
            request_id=rid,
            metadata=safe_metadata,
        )

    def _sanitize_metadata(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in meta.items():
            kl = k.lower()
            if isinstance(v, str) and kl in {"email", "ip"}:
                out[k] = encrypt_str(v)
            else:
                out[k] = v
        return out
