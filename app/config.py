import os
import secrets

class Settings:
    _raw_db: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./keyauth.db")
    # Render/Neon/Supabase give postgres:// or postgresql://, asyncpg needs postgresql+asyncpg://
    if _raw_db.startswith("postgres://"):
        DATABASE_URL: str = "postgresql+asyncpg://" + _raw_db[len("postgres://"):]
    elif _raw_db.startswith("postgresql://"):
        DATABASE_URL: str = "postgresql+asyncpg://" + _raw_db[len("postgresql://"):]
    else:
        DATABASE_URL: str = _raw_db
    # asyncpg uses ssl= not sslmode=
    DATABASE_URL = DATABASE_URL.replace("sslmode=require", "ssl=require")
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))

    _raw_key: str = os.getenv("ENCRYPTION_KEY", "")
    ENCRYPTION_KEY: bytes = _raw_key.encode().ljust(32, b"\0")[:32] if _raw_key else b"KeyAuthDefaultKey32Bytes123456"

    JWT_SECRET: str = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"

    TOKEN_EXPIRY_MINUTES: int = int(os.getenv("TOKEN_EXPIRY_MINUTES", "60"))
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", "15"))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))

    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin")

    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

settings = Settings()
