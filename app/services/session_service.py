from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Session
from app.services.crypto import generate_session_token


class SessionService:
    def __init__(self, db: AsyncSession, token_expiry_minutes: int = 60):
        self.db = db
        self.token_expiry = token_expiry_minutes

    async def create_session(
        self, app_id: int, user_id: int | None, hwid: str,
        ip: str, user_agent: str, version: str, platform: str
    ) -> Session:
        session = Session(
            session_id=generate_session_token(),
            application_id=app_id,
            user_id=user_id,
            hwid=hwid,
            ip_address=ip,
            user_agent=user_agent,
            version=version,
            platform=platform,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.token_expiry),
            is_valid=True,
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def validate_session(self, session_id: str, hwid: str) -> Session | None:
        result = await self.db.execute(
            select(Session).where(
                Session.session_id == session_id,
                Session.is_valid == True,
            )
        )
        session = result.scalar_one_or_none()
        if session is None:
            return None
        exp = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
        if exp < datetime.now(timezone.utc):
            session.is_valid = False
            await self.db.commit()
            return None
        if session.hwid and session.hwid != hwid:
            session.is_valid = False
            await self.db.commit()
            return None
        return session

    async def invalidate_session(self, session_id: str) -> None:
        result = await self.db.execute(
            select(Session).where(Session.session_id == session_id)
        )
        session = result.scalar_one_or_none()
        if session:
            session.is_valid = False
            await self.db.commit()

    async def get_active_count(self, app_id: int) -> int:
        result = await self.db.execute(
            select(Session).where(
                Session.application_id == app_id,
                Session.is_valid == True,
                Session.expires_at > datetime.now(timezone.utc),
            )
        )
        return len(result.scalars().all())

    async def get_session_user_id(self, session_id: str) -> int | None:
        result = await self.db.execute(
            select(Session).where(
                Session.session_id == session_id,
                Session.is_valid == True,
            )
        )
        session = result.scalar_one_or_none()
        return session.user_id if session else None
