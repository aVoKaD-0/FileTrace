import logging
import logging.config
import json
import time
import uuid
from contextvars import ContextVar


REQUEST_ID_CTX: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.request_id = REQUEST_ID_CTX.get()
        except Exception:
            record.request_id = "-"
        return True

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            log["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": JsonFormatter,
            },
            "uvicorn": {
                "format": "%(levelprefix)s %(asctime)s [request_id=%(request_id)s] %(message)s",
            },
        },
        "filters": {
            "request_id": {
                "()": RequestIdFilter,
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "filters": ["request_id"],
                "level": level,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": level,
        },
        "loggers": {
            "uvicorn": {"handlers": ["console"], "level": level, "propagate": False},
            "uvicorn.error": {"handlers": ["console"], "level": level, "propagate": False},
            "uvicorn.access": {"handlers": ["console"], "level": level, "propagate": False},
        },
    }
    logging.config.dictConfig(config)


def set_request_id(request_id: str | None = None) -> str:
    rid = request_id or str(uuid.uuid4())
    REQUEST_ID_CTX.set(rid)
    return rid


def clear_request_id() -> None:
    REQUEST_ID_CTX.set("-")
