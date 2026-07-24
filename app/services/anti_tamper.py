from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Log, Application, User


class AntiTamperService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def is_hwid_blacklisted(self, app_id: int, hwid: str) -> bool:
        result = await self.db.execute(select(Application).where(Application.id == app_id))
        app = result.scalar_one_or_none()
        if not app or not app.hwid_blacklist:
            return False
        blacklisted = [h.strip() for h in app.hwid_blacklist.split(",")]
        return hwid in blacklisted

    async def is_ip_whitelisted(self, app_id: int, ip: str) -> bool:
        result = await self.db.execute(select(Application).where(Application.id == app_id))
        app = result.scalar_one_or_none()
        if not app or not app.ip_whitelist:
            return True
        whitelisted = [i.strip() for i in app.ip_whitelist.split(",")]
        return ip in whitelisted

    async def log_activity(
        self, app_id: int, user_id: int | None, log_type: str,
        message: str, ip: str, hwid: str, metadata: str = ""
    ) -> None:
        log = Log(
            application_id=app_id,
            user_id=user_id,
            type=log_type,
            message=message,
            ip_address=ip,
            hwid=hwid,
            meta_info=metadata,
        )
        self.db.add(log)
        await self.db.commit()

    async def get_failed_logins(self, app_id: int, hwid: str, window_minutes: int = 15) -> int:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        result = await self.db.execute(
            select(Log).where(
                Log.application_id == app_id,
                Log.hwid == hwid,
                Log.type == "failed_login",
                Log.created_at > cutoff,
            )
        )
        return len(result.scalars().all())

    async def get_recent_logs(self, app_id: int, page: int = 1, per_page: int = 100) -> list[Log]:
        result = await self.db.execute(
            select(Log)
            .where(Log.application_id == app_id)
            .order_by(Log.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        return list(result.scalars().all())

    async def get_total_users(self, app_id: int) -> int:
        result = await self.db.execute(
            select(User).where(User.application_id == app_id)
        )
        return len(result.scalars().all())

    async def increment_downloads(self, app_id: int) -> None:
        result = await self.db.execute(select(Application).where(Application.id == app_id))
        app = result.scalar_one_or_none()
        if app:
            app.total_downloads += 1
            await self.db.commit()
