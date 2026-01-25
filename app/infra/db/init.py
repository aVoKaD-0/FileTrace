import os
from typing import List, Optional

from sqlalchemy import text
from app.infra.db.session import engine


def _split_sql_statements(sql: str) -> List[str]:
    parts = []
    buf = []
    for ch in sql:
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                parts.append(stmt)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


async def init_db_from_sql(sql_path: Optional[str] = None) -> None:
    if sql_path is None:
        sql_path = os.path.join("db", "init.sql")

    if not os.path.exists(sql_path):
        raise FileNotFoundError(sql_path)

    with open(sql_path, "r", encoding="utf-8") as f:
        raw = f.read()

    statements = _split_sql_statements(raw)
    async with engine.begin() as conn:
        for stmt in statements:
            await conn.execute(text(stmt))