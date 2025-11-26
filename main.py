import subprocess
from app.main import create_app
import time
import psycopg2
from psycopg2 import OperationalError
from app.config.db import DATABASE_URL

app = create_app()

def wait_for_postgres(timeout=60, delay=2):
    """Ожидание запуска PostgreSQL."""
    start_time = time.time()

    while True:
        try:
            conn = psycopg2.connect(**DATABASE_URL)
            conn.close()
            print("✅ PostgreSQL доступен!")
            return True
        except OperationalError as e:
            if time.time() - start_time > timeout:
                print("❌ PostgreSQL так и не поднялся!")
                raise e
            print("⏳ Ждём PostgreSQL...")
            time.sleep(delay)

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True
    )