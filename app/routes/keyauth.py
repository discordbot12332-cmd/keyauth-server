import json
import secrets

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import Application, User
from app.services.crypto import hash_password, verify_password
from app.services.license_service import LicenseService
from app.services.session_service import SessionService
from app.services.anti_tamper import AntiTamperService
from app.config import settings
from app.utc import utcnow

router = APIRouter(prefix="/api/1.3", tags=["keyauth"])


def _resp(success: bool, message: str, **extra):
    data = {"success": success, "message": message}
    data.update(extra)
    return data


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")


async def _params(request: Request) -> dict:
    """Accept KeyAuth form-urlencoded bodies, with query-param fallback."""
    p: dict = {}
    try:
        form = await request.form()
        for k, v in form.items():
            p[str(k)] = str(v)
    except Exception:
        pass
    for k, v in request.query_params.items():
        p.setdefault(str(k), str(v))
    try:
        body = await request.json()
        if isinstance(body, dict):
            for k, v in body.items():
                p.setdefault(str(k), str(v))
    except Exception:
        pass
    return p


async def _get_app(db: AsyncSession, ownerid: str, appname: str) -> Application | None:
    if ownerid:
        result = await db.execute(
            select(Application).where(
                (Application.owner_secret == ownerid) | (Application.secret_id == ownerid)
            )
        )
        app = result.scalar_one_or_none()
        if app:
            return app
    if appname:
        result = await db.execute(select(Application).where(Application.name == appname))
        return result.scalar_one_or_none()
    return None


async def _handle(action: str, p: dict, request: Request, db: AsyncSession) -> dict:
    ownerid = p.get("ownerid", "")
    appname = p.get("appname", "")
    app = await _get_app(db, ownerid, appname)
    if not app or not app.enabled:
        return _resp(False, "Invalid Application Credentials")

    sess_svc = SessionService(db, settings.TOKEN_EXPIRY_MINUTES)
    lic_svc = LicenseService(db)
    anti = AntiTamperService(db)
    ip = _ip(request)

    if action in ("init", ""):
        version = p.get("version", "")
        if app.min_version and version < app.min_version:
            return _resp(False, "Update required")
        session = await sess_svc.create_session(app.id, None, "", ip, _ua(request), version, "KeyAuth")
        return {
            "success": True,
            "code": 68,
            "message": "Initialized",
            "sessionid": session.session_id,
            "appinfo": {
                "numUsers": str(app.current_users),
                "numOnlineUsers": str(await sess_svc.get_active_count(app.id)),
                "numKeys": str(await lic_svc.count_licenses(app.id)),
                "version": app.min_version or "1.0",
                "customerPanelLink": "",
            },
            "newSession": True,
            "nonce": secrets.token_hex(16),
            "ownerid": ownerid,
        }

    if action == "license":
        sid = p.get("sessionid", "")
        key = p.get("key", "")
        hwid = p.get("hwid", "")
        user_id = await sess_svc.get_session_user_id(sid)
        ok, message, lic = await lic_svc.use_license(app.id, key, hwid, ip, user_id)
        if not ok:
            return _resp(False, message)
        return _resp(True, message, subscription=lic.subscription,
                     expiry=lic.expiry_time.isoformat() if lic.expiry_time else "")

    if action == "check":
        sid = p.get("sessionid", "")
        session = await sess_svc.validate_session(sid, p.get("hwid", ""))
        if not session:
            return _resp(False, "Invalid session")
        return _resp(True, "Valid session")

    if action == "login":
        username = p.get("username", "")
        password = p.get("password", "")
        hwid = p.get("hwid", "")
        result = await db.execute(
            select(User).where(User.username == username, User.application_id == app.id)
        )
        user = result.scalar_one_or_none()
        if not user or not verify_password(password, user.password_hash):
            await anti.log_activity(app.id, None, "failed_login", "Invalid username or password", ip, hwid)
            return _resp(False, "Invalid username or password")
        if user.banned:
            return _resp(False, f"Account banned: {user.ban_reason}")
        user.hwid = hwid
        user.last_login = utcnow()
        await db.commit()
        session = await sess_svc.create_session(app.id, user.id, hwid, ip, _ua(request), "", "KeyAuth")
        await anti.log_activity(app.id, user.id, "login", "User logged in", ip, hwid)
        return _resp(True, "Login success", username=username, sessionid=session.session_id)

    if action == "register":
        username = p.get("username", "")
        password = p.get("password", "")
        hwid = p.get("hwid", "")
        existing = await db.execute(
            select(User).where(User.username == username, User.application_id == app.id)
        )
        if existing.scalar_one_or_none():
            return _resp(False, "Username already taken")
        user = User(
            username=username, password_hash=hash_password(password),
            application_id=app.id, hwid=hwid, ip_address=ip,
        )
        db.add(user)
        app.current_users += 1
        await db.commit()
        await db.refresh(user)
        await anti.log_activity(app.id, user.id, "register", "User registered", ip, hwid)
        return _resp(True, "Register success")

    if action == "download":
        if not app.download_enabled:
            return _resp(False, "Download not enabled")
        await anti.increment_downloads(app.id)
        return _resp(True, "Success", content=app.download_url)

    if action == "webhook":
        if not app.webhook_url:
            return _resp(False, "No webhook configured")
        return _resp(True, "Success", content=app.webhook_url)

    if action == "log":
        await anti.log_activity(app.id, await sess_svc.get_session_user_id(p.get("sessionid", "")),
                                "keyauth_log", p.get("message", ""), ip, p.get("hwid", ""))
        return _resp(True, "Successfully sent log")

    if action == "var":
        return _resp(True, "Successfully fetched variables", variables={})

    if action == "sub":
        key = p.get("key", "")
        days = int(p.get("days", 0) or 0)
        if days <= 0:
            return _resp(False, "Days must be positive")
        ok, message, lic = await lic_svc.add_time(app.id, key, days)
        if not ok:
            return _resp(False, message)
        return _resp(True, message, expiry=lic.expiry_time.isoformat() if lic.expiry_time else "")

    if action == "fetchStats":
        return _resp(True, "Successfully fetched stats", stats={
            "numUsers": str(app.current_users),
            "numOnlineUsers": str(await sess_svc.get_active_count(app.id)),
            "numKeys": str(await lic_svc.count_licenses(app.id)),
        })

    if action == "logout":
        await sess_svc.invalidate_session(p.get("sessionid", ""))
        return _resp(True, "Logged out")

    return _resp(False, "Endpoint not found")


async def _infer_action(p: dict) -> str:
    if p.get("action"):
        return p["action"]
    if "key" in p or "license" in p:
        return "license"
    if "username" in p:
        return "register" if "license" in p else "login"
    if "message" in p and "sessionid" in p:
        return "log"
    if "sessionid" in p:
        return "check"
    return "init"


@router.post("")
async def keyauth_root(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _params(request)
    return await _handle(await _infer_action(p), p, request, db)


@router.post("/")
async def keyauth_root_slash(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _params(request)
    return await _handle(await _infer_action(p), p, request, db)


@router.post("/{action}")
async def keyauth_action(action: str, request: Request, db: AsyncSession = Depends(get_db)):
    p = await _params(request)
    return await _handle(action.lower(), p, request, db)
