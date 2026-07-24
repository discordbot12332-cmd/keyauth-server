import json
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import Application, User
from app.services.crypto import (
    generate_secret_id, generate_secret_key, generate_owner_secret,
)
from app.services.session_service import SessionService
from app.services.license_service import LicenseService
from app.services.anti_tamper import AntiTamperService
from app.config import settings

router = APIRouter(prefix="/api/admin", tags=["admin"])

VALID_SUBSCRIPTIONS = {"day", "weekly", "monthly", "yearly"}


def _resp(success: bool, message: str = "", data: str | None = None):
    return {"success": success, "message": message, "data": data}


def _check_auth(admin_secret: str) -> bool:
    return admin_secret == settings.ADMIN_PASSWORD


@router.post("/create-app")
async def create_app(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    admin_secret = body.get("adminSecret", "")
    if not _check_auth(admin_secret):
        return _resp(False, "Invalid admin credentials")

    name = body.get("name", "")
    max_users = body.get("maxUsers", 1000)
    webhook_url = body.get("webhookUrl", "")
    download_enabled = body.get("downloadEnabled", False)
    download_url = body.get("downloadUrl", "")

    existing = await db.execute(select(Application).where(Application.name == name))
    if existing.scalar_one_or_none():
        return _resp(False, "Application name already exists")

    app = Application(
        name=name,
        secret_id=generate_secret_id(),
        secret_key=generate_secret_key(),
        owner_secret=generate_owner_secret(),
        max_users=max_users,
        webhook_url=webhook_url,
        download_enabled=download_enabled,
        download_url=download_url,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    return _resp(True, "Application created", json.dumps({
        "name": app.name,
        "secret_id": app.secret_id,
        "secret_key": app.secret_key,
        "owner_secret": app.owner_secret,
        "max_users": app.max_users,
    }))


@router.post("/delete-app")
async def delete_app(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        return _resp(False, "Application not found")

    await db.delete(app)
    await db.commit()
    return _resp(True, "Application deleted")


@router.get("/list-apps")
async def list_apps(adminSecret: str = Query(...), db: AsyncSession = Depends(get_db)):
    if not _check_auth(adminSecret):
        return _resp(False, "Invalid admin credentials")

    result = await db.execute(select(Application).order_by(Application.created_at.desc()))
    apps = result.scalars().all()

    return _resp(True, data=json.dumps([{
        "id": a.id, "name": a.name, "secret_id": a.secret_id,
        "enabled": a.enabled, "current_users": a.current_users,
        "max_users": a.max_users, "total_downloads": a.total_downloads,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "sub_disabled": a.sub_disabled, "download_enabled": a.download_enabled,
    } for a in apps]))


@router.post("/toggle-app")
async def toggle_app(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        return _resp(False, "Application not found")

    app.enabled = not app.enabled
    await db.commit()
    return _resp(True, f"Application {'enabled' if app.enabled else 'disabled'}")


@router.post("/generate-license")
async def generate_license(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = body.get("appId")
    if app_id is None:
        return _resp(False, "appId is required")
    app_id = int(app_id)

    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        return _resp(False, "Application not found")

    lic_svc = LicenseService(db)
    subscription = body.get("subscription", "day")
    if subscription not in VALID_SUBSCRIPTIONS:
        return _resp(False, f"Invalid subscription. Must be one of: {', '.join(VALID_SUBSCRIPTIONS)}")
    expiry = body.get("expiry")
    if expiry:
        from datetime import datetime
        expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00")).replace(tzinfo=None)

    lic = await lic_svc.generate_license(
        app_id=app_id,
        subscription=subscription,
        max_uses=int(body.get("maxUses", 1)),
        expiry=expiry,
        note=body.get("note", ""),
    )
    return _resp(True, "License generated", json.dumps({"key": lic.key, "app_name": app.name}))


@router.post("/generate-bulk-licenses")
async def generate_bulk(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    if not app_id:
        return _resp(False, "appId is required")

    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        return _resp(False, "Application not found")

    lic_svc = LicenseService(db)
    count = int(body.get("count", 10))

    subscription = body.get("subscription", "day")
    if subscription not in VALID_SUBSCRIPTIONS:
        return _resp(False, f"Invalid subscription. Must be one of: {', '.join(VALID_SUBSCRIPTIONS)}")

    expiry = body.get("expiry")
    if expiry:
        from datetime import datetime
        expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00")).replace(tzinfo=None)

    licenses = await lic_svc.generate_bulk(
        app_id=app_id,
        subscription=subscription,
        max_uses=int(body.get("maxUses", 1)),
        expiry=expiry,
        note=body.get("note", ""),
        count=count,
    )
    return _resp(True, f"{len(licenses)} licenses generated", json.dumps({"keys": [l.key for l in licenses], "app_name": app.name}))


@router.post("/revoke-license")
async def revoke_license(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    result = await LicenseService(db).revoke_license(app_id, body.get("key", ""))
    return _resp(True, "License revoked" if result else "License not found")


@router.post("/delete-license")
async def delete_license(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    result = await LicenseService(db).delete_license(app_id, body.get("key", ""))
    return _resp(True, "License deleted" if result else "License not found")


@router.get("/list-licenses")
async def list_licenses(
    adminSecret: str = Query(...), appId: int = Query(...),
    page: int = Query(1), db: AsyncSession = Depends(get_db)
):
    if not _check_auth(adminSecret):
        return _resp(False, "Invalid admin credentials")

    lic_svc = LicenseService(db)
    licenses = await lic_svc.get_licenses(appId, page)
    total = await lic_svc.count_licenses(appId)
    active = await lic_svc.count_active(appId)

    return _resp(True, data=json.dumps({
        "licenses": [{
            "key": l.key, "subscription": l.subscription,
            "expiry": l.expiry_time.isoformat() if l.expiry_time else None,
            "used_count": l.used_count, "max_uses": l.max_uses,
            "disabled": l.disabled, "hwid": l.hwid, "note": l.note,
            "created_at": l.created_at.isoformat() if l.created_at else None,
            "last_used": l.last_used_at.isoformat() if l.last_used_at else None,
        } for l in licenses],
        "total": total, "active": active, "page": page,
    }))


@router.get("/logs")
async def get_logs(
    adminSecret: str = Query(...), appId: int = Query(...),
    page: int = Query(1), db: AsyncSession = Depends(get_db)
):
    if not _check_auth(adminSecret):
        return _resp(False, "Invalid admin credentials")

    logs = await AntiTamperService(db).get_recent_logs(appId, page)
    return _resp(True, data=json.dumps([{
        "type": l.type, "message": l.message, "ip": l.ip_address,
        "hwid": l.hwid, "created_at": l.created_at.isoformat() if l.created_at else None,
    } for l in logs]))


@router.get("/stats")
async def get_stats(
    adminSecret: str = Query(...), appId: int = Query(...),
    db: AsyncSession = Depends(get_db)
):
    if not _check_auth(adminSecret):
        return _resp(False, "Invalid admin credentials")

    anti = AntiTamperService(db)
    lic_svc = LicenseService(db)
    sess_svc = SessionService(db)

    return _resp(True, data=json.dumps({
        "total_licenses": await lic_svc.count_licenses(appId),
        "active_licenses": await lic_svc.count_active(appId),
        "total_users": await anti.get_total_users(appId),
        "active_sessions": await sess_svc.get_active_count(appId),
    }))


@router.post("/ban-user")
async def ban_user(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    result = await db.execute(
        select(User).where(
            User.username == body.get("username"),
            User.application_id == app_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        return _resp(False, "User not found")

    user.banned = True
    user.ban_reason = body.get("reason", "Banned by admin")
    await db.commit()
    return _resp(True, f"User {user.username} banned")


@router.post("/add-time")
async def add_time(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    if not _check_auth(body.get("adminSecret", "")):
        return _resp(False, "Invalid admin credentials")

    app_id = int(body.get("appId", 0))
    key = body.get("key", "")
    days = int(body.get("days", 0))
    if days <= 0:
        return _resp(False, "Days must be positive")

    lic_svc = LicenseService(db)
    success, message, lic = await lic_svc.add_time(app_id, key, days)
    if not success:
        return _resp(False, message)

    return _resp(True, message, json.dumps({
        "key": lic.key,
        "expiry": lic.expiry_time.isoformat() if lic.expiry_time else None,
    }))
