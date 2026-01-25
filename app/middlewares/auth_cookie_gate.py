from jose import jwt
from jose.exceptions import JWTError
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from app.config.auth import SECRET_KEY, ALGORITHM
from app.infra.db.session import AsyncSessionLocal
from app.services.user_service import UserService
from app.auth.auth import create_access_token


def install_cookie_auth_gate(app: FastAPI) -> None:
    @app.middleware("http")
    async def check_token(request: Request, call_next):
        def _is_public_path(path: str) -> bool:
            if path.startswith("/static/") or path.startswith("/media/") or path.startswith("/documents/"):
                return True
            if path in {"/", "/main/"}:
                return True
            return False

        async def _clear_auth_cookies(resp):
            resp.delete_cookie(key="refresh_token", path="/")
            resp.delete_cookie(key="access_token", path="/")
            return resp

        def _try_decode(token: str) -> bool:
            try:
                jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                return True
            except JWTError:
                return False

        path = request.url.path
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        is_authenticated = bool(access_token or refresh_token)

        if path == "/users/" and is_authenticated:
            return RedirectResponse(url="/main/")

        if _is_public_path(path):
            return await call_next(request)

        if (not is_authenticated) and path.startswith("/users/"):
            return await call_next(request)

        if not is_authenticated:
            return RedirectResponse(url="/users/")

        try:
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            if not access_token and not refresh_token:
                return RedirectResponse(url="/users/")

            if refresh_token:
                async with AsyncSessionLocal() as db2:
                    try:
                        user_service = UserService(db2)
                        user = await user_service.get_refresh_token(refresh_token=refresh_token)
                        if user is None:
                            return await _clear_auth_cookies(RedirectResponse(url="/users/"))
                    except Exception:
                        response = await call_next(request)
                        return await _clear_auth_cookies(response)

                    try:
                        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
                        user_id = payload.get("sub")
                        if not user_id:
                            return await _clear_auth_cookies(RedirectResponse(url="/users/"))
                    except JWTError:
                        return await _clear_auth_cookies(RedirectResponse(url="/users/"))

                    needs_new_access = (not access_token) or (not _try_decode(access_token))
                    if needs_new_access:
                        new_access_token = create_access_token({"sub": user_id})
                        response = await call_next(request)
                        response.set_cookie(
                            key="access_token",
                            value=new_access_token,
                            httponly=True,
                            samesite="Lax",
                            max_age=30 * 60,
                            secure=(request.url.scheme == "https"),
                            path="/",
                        )
                        return response

                    return await call_next(request)

            if access_token and not _try_decode(access_token):
                response = RedirectResponse(url="/users/")
                response.delete_cookie(key="access_token", path="/")
                return response

            return await call_next(request)

        except Exception:
            return RedirectResponse(url="/users/")
