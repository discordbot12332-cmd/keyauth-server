from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base
from app.utc import utcnow


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    secret_id = Column(String(32), unique=True, nullable=False, index=True)
    secret_key = Column(String(128), nullable=False)
    owner_secret = Column(String(128), nullable=False)

    enabled = Column(Boolean, default=True)
    max_users = Column(Integer, default=1000)
    current_users = Column(Integer, default=0)
    total_downloads = Column(Integer, default=0)

    webhook_url = Column(Text, default="")
    hwid_blacklist = Column(Text, default="")
    ip_whitelist = Column(Text, default="")

    sub_disabled = Column(Boolean, default=False)
    download_enabled = Column(Boolean, default=False)
    download_url = Column(Text, default="")

    created_at = Column(DateTime, default=utcnow)

    licenses = relationship("License", back_populates="application", cascade="all, delete-orphan")
    users = relationship("User", back_populates="application", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="application", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="application", cascade="all, delete-orphan")


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), nullable=False, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    subscription = Column(String(64), default="")
    expiry_time = Column(DateTime, nullable=True)
    max_uses = Column(Integer, default=1)
    used_count = Column(Integer, default=0)
    disabled = Column(Boolean, default=False)

    hwid = Column(String(128), default="")
    ip_list = Column(Text, default="")
    note = Column(Text, default="")

    created_at = Column(DateTime, default=utcnow)
    last_used_at = Column(DateTime, nullable=True)

    application = relationship("Application", back_populates="licenses")
    user = relationship("User", back_populates="licenses")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False)
    password_hash = Column(String(128), nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)

    hwid = Column(String(128), default="")
    is_admin = Column(Boolean, default=False)
    banned = Column(Boolean, default=False)
    ban_reason = Column(Text, default="")

    ip_address = Column(String(64), default="")
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)

    application = relationship("Application", back_populates="users")
    licenses = relationship("License", back_populates="user")
    sessions = relationship("Session", back_populates="user")
    logs = relationship("Log", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    hwid = Column(String(128), default="")
    ip_address = Column(String(64), default="")
    user_agent = Column(Text, default="")
    version = Column(String(32), default="")
    platform = Column(String(32), default="")

    is_valid = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)

    application = relationship("Application", back_populates="sessions")
    user = relationship("User", back_populates="sessions")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    type = Column(String(32), nullable=False, index=True)
    message = Column(Text, nullable=False)
    ip_address = Column(String(64), default="")
    hwid = Column(String(128), default="")
    meta_info = Column(Text, default="")

    created_at = Column(DateTime, default=utcnow, index=True)

    application = relationship("Application", back_populates="logs")
    user = relationship("User", back_populates="logs")
