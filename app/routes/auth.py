import json
import time as _time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import Application, User
from app.services.crypto import decrypt_aes, verify_password, hash_password, verify_hmac
from app.services.session_service import SessionService
from app.services.license_service import LicenseService
from app.services.anti_tamper import AntiTamperService
from app.config import settings
from app.utc import utcnow, utc_add

router = APIRouter(prefix="/api/v1", tags=["auth"])


def _fail_parse(message: str = ""):
    return {"success": False, "message": message, "sessionId": None, "data": None}


async def _parse(request: Request) -> dict:
    """Parse request — AES+HMAC+timestamp (new) or legacy formats."""
    body = await request.json()
    data = body.get("data", "")
    ts = body.get("ts")
    sig = body.get("sig", "")

    # New encrypted + signed format
    if ts is not None and isinstance(data, str) and data and sig:
        now_ms = int(_time.time() * 1000)
        if abs(now_ms - int(ts)) > 60000:
            raise Exception("Request expired")
        try:
            plaintext = decrypt_aes(data)
        except Exception:
            raise Exception("Decryption failed")
        enc_key = settings.ENCRYPTION_KEY.decode() if isinstance(settings.ENCRYPTION_KEY, bytes) else str(settings.ENCRYPTION_KEY)
        if not verify_hmac(data + str(ts), enc_key, sig):
            raise Exception("Invalid signature")
        return json.loads(plaintext)

    # Legacy: dict passthrough
    if isinstance(data, dict):
        return data

    # Legacy: try decrypt or raw JSON string
    if isinstance(data, str) and data:
        try:
            decoded = decrypt_aes(data)
            return json.loads(decoded)
        except Exception:
            try:
                return json.loads(data)
            except Exception:
                pass
    return body


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")


def _ok(message: str = "", session_id: str = None, data: str = None):
    return {"success": True, "message": message, "sessionId": session_id, "data": data}


def _fail(message: str = ""):
    return {"success": False, "message": message, "sessionId": None, "data": None}

def _fail_update_required(download_url: str = ""):
    return {"success": False, "message": "Update required", "sessionId": None, "data": json.dumps({"update_required": True, "download_url": download_url})}


async def _validate(db: AsyncSession, session_id: str, hwid: str) -> Application | None:
    if not session_id:
        return None
    sess_svc = SessionService(db, settings.TOKEN_EXPIRY_MINUTES)
    session = await sess_svc.validate_session(session_id, hwid)
    if not session:
        return None
    result = await db.execute(select(Application).where(Application.id == session.application_id))
    return result.scalar_one_or_none()


async def _session_uid(db: AsyncSession, session_id: str) -> int | None:
    return await SessionService(db).get_session_user_id(session_id)


# ===================== ENDPOINTS =====================

@router.post("/init")
async def init_app(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    secret_id = p.get("secret_id", "")
    hwid = p.get("hwid", "")
    version = p.get("version", "")
    platform = p.get("platform", "")

    result = await db.execute(select(Application).where(Application.secret_id == secret_id))
    app = result.scalar_one_or_none()
    if not app or not app.enabled:
        return _fail("Application not found or disabled")

    ip = _ip(request)
    anti = AntiTamperService(db)

    if app.ip_whitelist and not await anti.is_ip_whitelisted(app.id, ip):
        return _fail("IP not whitelisted")
    if await anti.is_hwid_blacklisted(app.id, hwid):
        return _fail("HWID blacklisted")

    if app.min_version and version < app.min_version:
        return _fail_update_required(app.download_url)

    sess_svc = SessionService(db, settings.TOKEN_EXPIRY_MINUTES)
    session = await sess_svc.create_session(app.id, None, hwid, ip, _ua(request), version, platform)
    active = await sess_svc.get_active_count(app.id)
    await anti.log_activity(app.id, None, "init", "Application initialized", ip, hwid)

    return _ok("Application initialized", session.session_id, json.dumps({
        "app_name": app.name, "active_users": active,
        "total_downloads": app.total_downloads,
        "sub_disabled": app.sub_disabled,
        "download_enabled": app.download_enabled,
        "download_url": app.download_url,
    }))


@router.post("/login")
async def login(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    username = p.get("username", "")
    password = p.get("password", "")
    hwid = p.get("hwid", "")
    ip = _ip(request)

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")

    result = await db.execute(select(User).where(User.username == username, User.application_id == app.id))
    user = result.scalar_one_or_none()
    anti = AntiTamperService(db)

    if not user:
        await anti.log_activity(app.id, None, "failed_login", "User not found", ip, hwid)
        return _fail("Invalid username or password")

    if user.banned:
        return _fail(f"Account banned: {user.ban_reason}")
    if user.locked_until:
        if user.locked_until > utcnow():
            return _fail("Account temporarily locked")

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = utc_add(minutes=settings.LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
        await db.commit()
        await anti.log_activity(app.id, user.id, "failed_login", "Invalid password", ip, hwid)
        return _fail("Invalid username or password")

    if user.hwid and user.hwid != hwid:
        await anti.log_activity(app.id, user.id, "hwid_mismatch",
                                f"HWID changed from {user.hwid} to {hwid}", ip, hwid)

    user.hwid = hwid
    user.last_login = utcnow()
    user.ip_address = ip
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    sess_svc = SessionService(db, settings.TOKEN_EXPIRY_MINUTES)
    session = await sess_svc.create_session(app.id, user.id, hwid, ip, _ua(request), "", "")
    await anti.log_activity(app.id, user.id, "login", "User logged in", ip, hwid)

    return _ok("Login successful", session.session_id, json.dumps({
        "username": user.username, "is_admin": user.is_admin,
    }))


@router.post("/register")
async def register(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    username = p.get("username", "")
    password = p.get("password", "")
    hwid = p.get("hwid", "")
    ip = _ip(request)

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")

    existing = await db.execute(select(User).where(User.username == username, User.application_id == app.id))
    if existing.scalar_one_or_none():
        return _fail("Username already taken")

    user = User(
        username=username, password_hash=hash_password(password),
        application_id=app.id, hwid=hwid, ip_address=ip,
    )
    db.add(user)
    app.current_users += 1
    await db.commit()
    await db.refresh(user)

    sess_svc = SessionService(db, settings.TOKEN_EXPIRY_MINUTES)
    session = await sess_svc.create_session(app.id, user.id, hwid, ip, _ua(request), "", "")
    await AntiTamperService(db).log_activity(app.id, user.id, "register", "User registered", ip, hwid)

    return _ok("Registration successful", session.session_id, json.dumps({"username": user.username}))


@router.post("/license")
async def activate_license(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    key = p.get("key", "")
    hwid = p.get("hwid", "")
    ip = _ip(request)

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")
    if app.sub_disabled:
        return _fail("Subscriptions disabled for this application")

    user_id = await _session_uid(db, sid)
    lic_svc = LicenseService(db)
    success, message, lic = await lic_svc.use_license(app.id, key, hwid, ip, user_id)

    anti = AntiTamperService(db)
    if success:
        await anti.log_activity(app.id, user_id, "license", f"License activated: {lic.subscription}", ip, hwid)
        return _ok(message, data=json.dumps({
            "subscription": lic.subscription,
            "expiry": lic.expiry_time.isoformat() if lic.expiry_time else None,
            "key": lic.key,
        }))
    else:
        await anti.log_activity(app.id, user_id, "failed_license", message, ip, hwid)
        return _fail(message)


@router.post("/check")
async def check_session(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    hwid = p.get("hwid", "")

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")

    user_id = await _session_uid(db, sid)
    user_data = None
    if user_id:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user:
            user_data = json.dumps({
                "username": user.username, "is_admin": user.is_admin,
                "hwid": user.hwid,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            })
    return _ok("Session valid", data=user_data)


@router.post("/download")
async def download(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    hwid = p.get("hwid", "")

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")
    if not app.download_enabled:
        return _fail("Download not enabled")

    await AntiTamperService(db).increment_downloads(app.id)
    return _ok("Download URL", data=json.dumps({"download_url": app.download_url}))


@router.post("/webhook")
async def get_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    sid = p.get("session_id", "")
    hwid = p.get("hwid", "")

    app = await _validate(db, sid, hwid)
    if not app:
        return _fail("Invalid session")
    if not app.webhook_url:
        return _fail("No webhook configured")

    return _ok("Webhook URL", data=json.dumps({"webhook_url": app.webhook_url}))


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    p = await _parse(request)
    await SessionService(db).invalidate_session(p.get("session_id", ""))
    return _ok("Logged out")
