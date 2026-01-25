import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import redis
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.auth import uuid_by_token
from app.infra.db.deps import get_db
from app.core.settings import settings
from app.services.audit_service import AuditService
from app.services.user_service import UserService
from app.utils.file_operations import FileOperations
from app.utils.logging import Logger
from app.celery_app import download_url_and_enqueue_analysis_task


router = APIRouter()


class UrlRequest(BaseModel):
    url: str


class UrlDownloadRequest(BaseModel):
    url: str
    ticket: Optional[str] = None


def _normalize_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        raise HTTPException(status_code=400, detail="URL не указан")
    parsed = urlparse(u)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Разрешены только http/https ссылки")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Некорректный URL")
    return u


def _is_ip_private_or_local(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return True


def _resolve_host_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    ips = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and len(sockaddr) >= 1:
            ips.append(sockaddr[0])
    return list(dict.fromkeys(ips))


def _enforce_ssrf_protection(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Некорректный URL")

    if host.lower() in {"localhost"}:
        raise HTTPException(status_code=400, detail="Запрещено проверять localhost")

    try:
        ipaddress.ip_address(host)
        if _is_ip_private_or_local(host):
            raise HTTPException(status_code=400, detail="Запрещено проверять локальные/приватные IP")
        resolved_ips = [host]
    except ValueError:
        resolved_ips = _resolve_host_ips(host)

    if not resolved_ips:
        raise HTTPException(status_code=400, detail="Не удалось определить IP адрес хоста")

    for ip in resolved_ips:
        if _is_ip_private_or_local(ip):
            raise HTTPException(status_code=400, detail="Запрещено проверять локальные/приватные IP")

    return {"host": host, "resolved_ips": resolved_ips}


def _url_rate_limit_key(user_id: str) -> str:
    return f"filetrace:url_rate:{user_id}"


def _check_url_rate_limit(user_id: str) -> None:
    limit = int(getattr(settings, "URL_RATE_LIMIT_PER_MINUTE", 1) or 1)
    if limit < 1:
        return

    r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    key = _url_rate_limit_key(user_id)

    now = int(time.time())
    window = now // 60
    window_key = f"{key}:{window}"

    try:
        cnt = r.incr(window_key)
        if cnt == 1:
            r.expire(window_key, 70)
        if cnt > limit:
            raise HTTPException(status_code=429, detail="Слишком много запросов. Попробуйте позже")
    except HTTPException:
        raise
    except Exception:
        return


def _download_ticket_key(user_id: str, ticket: str) -> str:
    return f"filetrace:url_download_ticket:{user_id}:{ticket}"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sign_ticket(payload: Dict[str, Any]) -> str:
    secret = (getattr(settings, "HMAC_KEY", None) or getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    if not secret:
        raise RuntimeError("No secret for ticket signing")

    msg = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return _b64url_encode(msg) + "." + _b64url_encode(sig)


def _verify_ticket(token: str) -> Dict[str, Any]:
    if "." not in token:
        raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно")
    part_msg, part_sig = token.split(".", 1)
    msg = _b64url_decode(part_msg)
    sig = _b64url_decode(part_sig)

    secret = (getattr(settings, "HMAC_KEY", None) or getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    if not secret:
        raise HTTPException(status_code=503, detail="Сервис подтверждения временно недоступен")

    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно")

    try:
        data = json.loads(msg.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно")

    return data


def _issue_download_ticket(user_id: str, url: str) -> Optional[str]:
    try:
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        ticket = uuid.uuid4().hex
        key = _download_ticket_key(user_id, ticket)
        r.set(key, url, ex=5 * 60)
        return ticket
    except Exception:
        try:
            exp = int(time.time()) + 5 * 60
            return _sign_ticket({"uid": user_id, "url": url, "exp": exp})
        except Exception:
            return None


def _consume_download_ticket(user_id: str, ticket: str, url: str) -> None:
    if not ticket:
        raise HTTPException(status_code=403, detail="Требуется подтверждение проверки ссылки")

    if "." in ticket:
        data = _verify_ticket(ticket)
        exp = int(data.get("exp") or 0)
        if exp and int(time.time()) > exp:
            raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно или истекло")
        if str(data.get("uid") or "") != str(user_id) or str(data.get("url") or "") != str(url):
            raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно")
        return

    try:
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        key = _download_ticket_key(user_id, ticket)
        stored = r.get(key)
        if not stored or stored != url:
            raise HTTPException(status_code=403, detail="Подтверждение проверки ссылки недействительно или истекло")
        r.delete(key)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Сервис подтверждения временно недоступен")


def _max_download_bytes() -> int:
    return int(getattr(settings, "URL_MAX_DOWNLOAD_BYTES", 50 * 1024 * 1024) or 50 * 1024 * 1024)


def _is_allowed_exe(url: str) -> bool:
    filename = (urlparse(url).path.split("/")[-1] or "").lower()
    return filename.endswith(".exe")


def _enforce_url_file_policy(final_url: str, content_length: Optional[int]) -> Dict[str, Any]:
    max_bytes = _max_download_bytes()
    errors: List[str] = []

    if not _is_allowed_exe(final_url):
        errors.append("Разрешены только .exe файлы")

    if isinstance(content_length, int) and content_length > 0 and max_bytes > 0 and content_length > max_bytes:
        errors.append(f"Слишком большой файл по ссылке (лимит {max_bytes} bytes)")

    return {
        "can_download": len(errors) == 0,
        "policy_errors": errors,
        "max_download_bytes": max_bytes,
        "allowed_extension": ".exe",
    }


def _fetch_head_or_range(url: str, *, timeout_s: int, max_redirects: int) -> Dict[str, Any]:
    session = requests.Session()
    session.max_redirects = max_redirects

    headers = {
        "User-Agent": "FileTrace/1.0",
        "Accept": "*/*",
    }

    try:
        resp = session.head(url, allow_redirects=True, timeout=timeout_s, headers=headers)
        final_url = str(resp.url)
        return {
            "final_url": final_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers or {}),
            "method": "HEAD",
        }
    except Exception:
        pass

    try:
        resp = session.get(
            url,
            allow_redirects=True,
            timeout=timeout_s,
            headers={**headers, "Range": "bytes=0-0"},
            stream=True,
        )
        final_url = str(resp.url)
        return {
            "final_url": final_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers or {}),
            "method": "GET_RANGE",
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Не удалось получить метаданные: {str(e)}")


def _vt_url_report(url: str) -> Optional[Dict[str, Any]]:
    api_key = getattr(settings, "VT_API_KEY", None)
    if not api_key:
        return None

    try:
        s = requests.Session()
        headers = {"x-apikey": api_key}
        submit = s.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15,
        )
        if not submit.ok:
            return {"ok": False, "error": f"VT submit failed: {submit.status_code}", "raw": submit.text}

        data = submit.json()
        analysis_id = ((data or {}).get("data") or {}).get("id")
        if not analysis_id:
            return {"ok": False, "error": "VT did not return analysis id"}

        report = s.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=20,
        )
        if not report.ok:
            return {"ok": False, "error": f"VT report failed: {report.status_code}", "raw": report.text}

        rep = report.json()
        stats = (((rep or {}).get("data") or {}).get("attributes") or {}).get("stats") or {}
        return {"ok": True, "analysis_id": analysis_id, "stats": stats}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _yandex_sb_lookup(url: str) -> Optional[Dict[str, Any]]:
    api_key = getattr(settings, "YANDEX_SB_API_KEY", None)
    if not api_key:
        return None

    body = {
        "client": {
            "clientId": "filetrace",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(
            f"https://sba.yandex.net/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=15,
        )
        if not r.ok:
            return {"ok": False, "error": f"Yandex SB failed: {r.status_code}", "raw": r.text}
        data = r.json() if r.text else {}
        matches = data.get("matches") if isinstance(data, dict) else None
        return {"ok": True, "matches": matches or []}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _aggregate_verdict(vt: Optional[Dict[str, Any]], ysb: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    verdict = "unknown"
    reasons: List[str] = []

    vt_mal = 0
    vt_susp = 0
    if vt and vt.get("ok"):
        stats = vt.get("stats") or {}
        vt_mal = int(stats.get("malicious") or 0)
        vt_susp = int(stats.get("suspicious") or 0)

    y_matches = 0
    if ysb and ysb.get("ok"):
        y_matches = len(ysb.get("matches") or [])

    if y_matches > 0:
        verdict = "malicious"
        reasons.append("yandex_safe_browsing_match")

    if vt_mal > 0:
        verdict = "malicious"
        reasons.append("virustotal_malicious")
    elif verdict != "malicious" and vt_susp > 0:
        verdict = "suspicious"
        reasons.append("virustotal_suspicious")

    if verdict == "unknown" and ((vt and vt.get("ok")) or (ysb and ysb.get("ok"))):
        verdict = "clean"

    return {
        "verdict": verdict,
        "reasons": reasons,
        "vt": vt,
        "yandex": ysb,
    }


@router.post("/url/meta")
async def url_meta(request: Request, payload: UrlRequest):
    user_id = uuid_by_token(request.cookies.get("refresh_token"))
    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")

    _check_url_rate_limit(str(user_id))

    url = _normalize_url(payload.url)
    ssrf = _enforce_ssrf_protection(url)

    meta = _fetch_head_or_range(
        url,
        timeout_s=int(getattr(settings, "URL_META_TIMEOUT_SECONDS", 10) or 10),
        max_redirects=int(getattr(settings, "URL_MAX_REDIRECTS", 5) or 5),
    )

    headers = meta.get("headers") or {}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    content_length = headers.get("Content-Length") or headers.get("content-length")
    last_modified = headers.get("Last-Modified") or headers.get("last-modified")

    content_length_int = int(content_length) if str(content_length or "").isdigit() else None
    final_url = meta.get("final_url")
    policy = _enforce_url_file_policy(final_url or url, content_length_int)

    return JSONResponse(
        {
            "url": url,
            "final_url": meta.get("final_url"),
            "status_code": meta.get("status_code"),
            "method": meta.get("method"),
            "host": ssrf.get("host"),
            "resolved_ips": ssrf.get("resolved_ips"),
            "content_type": content_type,
            "content_length": content_length_int,
            "last_modified": last_modified,
            **policy,
        }
    )


@router.post("/url/check")
async def url_check(request: Request, payload: UrlRequest, db: AsyncSession = Depends(get_db)):
    user_id = uuid_by_token(request.cookies.get("refresh_token"))
    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")

    _check_url_rate_limit(str(user_id))

    url = _normalize_url(payload.url)
    _enforce_ssrf_protection(url)

    meta = _fetch_head_or_range(
        url,
        timeout_s=int(getattr(settings, "URL_META_TIMEOUT_SECONDS", 10) or 10),
        max_redirects=int(getattr(settings, "URL_MAX_REDIRECTS", 5) or 5),
    )
    headers = meta.get("headers") or {}
    content_length = headers.get("Content-Length") or headers.get("content-length")
    content_length_int = int(content_length) if str(content_length or "").isdigit() else None
    final_url = meta.get("final_url") or url
    policy = _enforce_url_file_policy(final_url, content_length_int)

    vt = _vt_url_report(url)
    ysb = _yandex_sb_lookup(url)
    agg = _aggregate_verdict(vt, ysb)

    ticket = _issue_download_ticket(str(user_id), url) if policy.get("can_download") and agg.get("verdict") != "malicious" else None

    await AuditService(db).log(
        request=request,
        event_type="url.checked",
        user_id=str(user_id),
        metadata={
            "url": url,
            "verdict": agg.get("verdict"),
            "reasons": agg.get("reasons"),
        },
    )

    return JSONResponse({"url": url, "final_url": final_url, "content_length": content_length_int, **policy, **agg, "ticket": ticket})


def _download_stream(url: str, *, timeout_s: int, max_bytes: int) -> bytes:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FileTrace/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    try:
        s = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        s.mount("http://", HTTPAdapter(max_retries=retry))
        s.mount("https://", HTTPAdapter(max_retries=retry))

        timeout = (min(10, timeout_s), timeout_s)

        with s.get(url, stream=True, timeout=timeout, headers=headers, allow_redirects=True) as r:
            r.raise_for_status()
            cl = r.headers.get("Content-Length") or r.headers.get("content-length")
            if str(cl or "").isdigit() and max_bytes > 0 and int(cl) > max_bytes:
                raise HTTPException(status_code=413, detail=f"Слишком большой файл по ссылке (лимит {max_bytes} bytes)")
            buf = bytearray()
            for chunk in r.iter_content(chunk_size=1024 * 256):
                if not chunk:
                    continue
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise HTTPException(status_code=413, detail="Слишком большой файл по ссылке")
                if len(buf) >= 2 and buf[0:2] != b"MZ":
                    raise HTTPException(status_code=400, detail="Файл по ссылке не похож на Windows PE (.exe)")
            return bytes(buf)
    except HTTPException:
        raise
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail="Не удалось скачать файл: превышено время ожидания ответа сервера")
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(status_code=504, detail="Не удалось скачать файл: превышено время ожидания соединения")
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "ConnectionResetError" in msg or "10054" in msg:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Не удалось скачать файл: удаленный хост разорвал соединение. "
                    "Сайт может блокировать автоматическое скачивание (антибот/ограничения). "
                    "Попробуйте скачать файл вручную и загрузить его через форму."
                ),
            )
        raise HTTPException(status_code=502, detail=f"Не удалось скачать файл: ошибка соединения ({msg})")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Не удалось скачать файл: {str(e)}")


@router.post("/url/download-and-analyze")
async def url_download_and_analyze(request: Request, payload: UrlDownloadRequest, db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        refresh_token = request.cookies.get("refresh_token")
        uuid_user = uuid_by_token(refresh_token)
        if not uuid_user:
            raise HTTPException(status_code=401, detail="unauthorized")

        _check_url_rate_limit(str(uuid_user))

        url = _normalize_url(payload.url)
        _enforce_ssrf_protection(url)

        _consume_download_ticket(str(uuid_user), payload.ticket or "", url)

        meta = _fetch_head_or_range(
            url,
            timeout_s=int(getattr(settings, "URL_META_TIMEOUT_SECONDS", 10) or 10),
            max_redirects=int(getattr(settings, "URL_MAX_REDIRECTS", 5) or 5),
        )
        headers = meta.get("headers") or {}
        content_length = headers.get("Content-Length") or headers.get("content-length")
        content_length_int = int(content_length) if str(content_length or "").isdigit() else None
        final_url = meta.get("final_url") or url
        policy = _enforce_url_file_policy(final_url, content_length_int)
        if not policy.get("can_download"):
            raise HTTPException(status_code=400, detail="; ".join(policy.get("policy_errors") or ["Скачивание запрещено"]))

        pipeline_version = settings.PIPELINE_VERSION
        run_id = FileOperations.run_ID()

        filename = (urlparse(final_url).path.split("/")[-1] or "downloaded.exe")
        if len(filename) > 200:
            filename = filename[:200]

        if not filename.lower().endswith(".exe"):
            raise HTTPException(status_code=400, detail="Разрешены только .exe файлы")

        await userservice.create_hash_analysis(
            user_id=uuid_user,
            filename=filename,
            status="queued",
            analysis_id=run_id,
            file_hash="",
            pipeline_version=pipeline_version,
        )
        await userservice.subscribe_user_to_analysis(analysis_id=run_id, user_id=uuid_user)
        await userservice.create_result(run_id)

        await AuditService(db).log(
            request=request,
            event_type="analysis.url_queued",
            user_id=str(uuid_user),
            metadata={
                "url": url,
                "filename": filename,
                "analysis_id": str(run_id),
                "file_hash": "",
                "pipeline_version": pipeline_version,
                "download_bytes": None,
            },
        )

        task = download_url_and_enqueue_analysis_task.delay(url, str(run_id), str(uuid_user), filename, pipeline_version)
        Logger.log(f"URL download queued. ID: {run_id}, task_id: {task.id}")

        return JSONResponse(
            {
                "status": "queued",
                "analysis_id": str(run_id),
                "task_id": task.id,
                "filename": filename,
                "download_bytes": None,
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        Logger.log(f"Ошибка при анализе URL: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
