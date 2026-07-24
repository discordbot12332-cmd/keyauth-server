from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import License
from app.services.crypto import generate_license_key

SUBSCRIPTION_DURATIONS = {
    "day": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
    "yearly": timedelta(days=365),
}


class LicenseService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_license(
        self, app_id: int, subscription: str = "day", max_uses: int = 1,
        expiry: datetime | None = None, note: str = ""
    ) -> License:
        if not expiry and subscription in SUBSCRIPTION_DURATIONS:
            expiry = datetime.now(timezone.utc) + SUBSCRIPTION_DURATIONS[subscription]
        lic = License(
            key=generate_license_key(),
            application_id=app_id,
            subscription=subscription,
            max_uses=max_uses,
            expiry_time=expiry,
            note=note,
        )
        self.db.add(lic)
        await self.db.commit()
        await self.db.refresh(lic)
        return lic

    async def generate_bulk(
        self, app_id: int, subscription: str, max_uses: int,
        expiry: datetime | None, note: str, count: int
    ) -> list[License]:
        if not expiry and subscription in SUBSCRIPTION_DURATIONS:
            expiry = datetime.now(timezone.utc) + SUBSCRIPTION_DURATIONS[subscription]
        licenses = []
        for _ in range(count):
            lic = License(
                key=generate_license_key(),
                application_id=app_id,
                subscription=subscription,
                max_uses=max_uses,
                expiry_time=expiry,
                note=note,
            )
            self.db.add(lic)
            licenses.append(lic)
        await self.db.commit()
        for lic in licenses:
            await self.db.refresh(lic)
        return licenses

    async def use_license(
        self, app_id: int, license_key: str, hwid: str, ip: str, user_id: int | None
    ) -> tuple[bool, str, License | None]:
        result = await self.db.execute(
            select(License).where(
                License.key == license_key,
                License.application_id == app_id,
            )
        )
        lic = result.scalar_one_or_none()
        if lic is None:
            return False, "Invalid license key", None
        if lic.disabled:
            return False, "License is disabled", None
        if lic.expiry_time and lic.expiry_time < datetime.now(timezone.utc):
            return False, "License has expired", None
        if lic.used_count >= lic.max_uses and lic.max_uses != -1:
            return False, "License maximum uses reached", None
        if lic.hwid and lic.hwid != hwid:
            return False, "License bound to different HWID", None

        if not lic.hwid:
            lic.hwid = hwid
        if user_id and lic.user_id is None:
            lic.user_id = user_id

        lic.used_count += 1
        lic.last_used_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(lic)
        return True, "License activated", lic

    async def revoke_license(self, app_id: int, license_key: str) -> bool:
        result = await self.db.execute(
            select(License).where(
                License.key == license_key,
                License.application_id == app_id,
            )
        )
        lic = result.scalar_one_or_none()
        if not lic:
            return False
        lic.disabled = True
        await self.db.commit()
        return True

    async def delete_license(self, app_id: int, license_key: str) -> bool:
        result = await self.db.execute(
            select(License).where(
                License.key == license_key,
                License.application_id == app_id,
            )
        )
        lic = result.scalar_one_or_none()
        if not lic:
            return False
        await self.db.delete(lic)
        await self.db.commit()
        return True

    async def get_licenses(self, app_id: int, page: int = 1, per_page: int = 50) -> list[License]:
        result = await self.db.execute(
            select(License)
            .where(License.application_id == app_id)
            .order_by(License.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        return list(result.scalars().all())

    async def count_licenses(self, app_id: int) -> int:
        result = await self.db.execute(
            select(License).where(License.application_id == app_id)
        )
        return len(result.scalars().all())

    async def count_active(self, app_id: int) -> int:
        result = await self.db.execute(
            select(License).where(
                License.application_id == app_id,
                License.disabled == False,
                (License.expiry_time == None) | (License.expiry_time > datetime.now(timezone.utc)),
            )
        )
        return len(result.scalars().all())

    async def add_time(self, app_id: int, license_key: str, days: int) -> tuple[bool, str, License | None]:
        result = await self.db.execute(
            select(License).where(
                License.key == license_key,
                License.application_id == app_id,
            )
        )
        lic = result.scalar_one_or_none()
        if not lic:
            return False, "License not found", None
        if lic.disabled:
            return False, "License is disabled", None
        now = datetime.now(timezone.utc)
        expiry = lic.expiry_time
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry and expiry < now:
            lic.expiry_time = now + timedelta(days=days)
        elif expiry:
            lic.expiry_time = expiry + timedelta(days=days)
        else:
            lic.expiry_time = now + timedelta(days=days)
        await self.db.commit()
        await self.db.refresh(lic)
        return True, f"Added {days} days", lic
