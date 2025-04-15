from enum import Enum
from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime, timezone
from app.core.database import Base


# Enum for user roles
class Role(str, Enum):
    ADMIN = "admin"
    USERS = "users"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    address = Column(String, nullable=True)
    state = Column(String, nullable=True)
    country = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)
    avatar = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    gender = Column(String, nullable=True)
    role = Column(String, nullable=False, default=Role.USERS.value)
    is_verified = Column(Boolean, default=False)
    two_factor_enabled = Column(Boolean, default=False)
    is_oauth = Column(Boolean, default=False)
    login_provider = Column(String, nullable=True, default="email")
    profile_completed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    activities = relationship(
        "Activity", back_populates="user", cascade="all, delete-orphan")


class ActivityType(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class Activity(Base):
    __tablename__ = "activities"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    description = Column(String, nullable=False)
    activity_type = Column(String, nullable=False,
                           default=ActivityType.CREATE.value)
    created_at = Column(DateTime, default=lambda: datetime.now(
        timezone.utc), nullable=False)

    user_id = Column(UUID(as_uuid=True), ForeignKey(
        "users.id", ondelete="CASCADE"), nullable=False)

    user = relationship("User", back_populates="activities")
