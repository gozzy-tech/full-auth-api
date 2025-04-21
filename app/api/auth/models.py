from enum import Enum
from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime, timezone
from app.core.database import Base


# Enum for user roles
class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


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
    role = Column(String, nullable=False, default=Role.USER.value)
    is_verified = Column(Boolean, default=False)
    two_factor_enabled = Column(Boolean, default=False)
    is_oauth = Column(Boolean, default=False)
    login_provider = Column(String, nullable=True, default="email")
    profile_completed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(
        timezone.utc), nullable=False)

    activities = relationship(
        "Activity", back_populates="user", cascade="all, delete-orphan")
    
    two_factor_confirmation = relationship(
        "TwoFactorConfirmation", back_populates="user", uselist=False, cascade="all, delete-orphan")


class VerificationToken(Base):
    __tablename__ = "verification_token"
    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, nullable=False)
    expires = Column(DateTime(timezone=True), default=lambda: datetime.now(
        timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("email", "token", name="uq_verification_email_token"),
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_token"
    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, nullable=False)
    expires = Column(DateTime(timezone=True), default=lambda: datetime.now(
        timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("email", "token", name="uq_password_email_token"),
    )


class TwoFactorToken(Base):
    __tablename__ = "two_factor_token"
    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, nullable=False)
    expires = Column(DateTime(timezone=True), default=lambda: datetime.now(
        timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("email", "token", name="uq_2fa_email_token"),
    )


class TwoFactorConfirmation(Base):
    __tablename__ = "two_factor_confirmation"
    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey(
        "users.id", ondelete="CASCADE"), nullable=False)  # Ensure correct foreign key reference

    user = relationship("User", back_populates="two_factor_confirmation")

    __table_args__ = (
        UniqueConstraint("user_id", name="uq_2fa_user"),
    )



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
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(
        timezone.utc), nullable=False)

    user_id = Column(UUID(as_uuid=True), ForeignKey(
        "users.id", ondelete="CASCADE"), nullable=False)

    user = relationship("User", back_populates="activities")
