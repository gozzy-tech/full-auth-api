from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select


from ..models import (
    TwoFactorConfirmation,
    VerificationToken,
    PasswordResetToken,
    TwoFactorToken,
)

# ---------------------------------------------
# Token Service
# ---------------------------------------------


class TokenService:
    # Generate Verification Token
    async def generate_verification_token(self, email: str, db: AsyncSession) -> VerificationToken:
        token = str(secrets.randbelow(899999) + 100000)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        # Check for existing token
        result = await db.execute(
            select(VerificationToken).where(VerificationToken.email == email)
        )
        existing = result.scalars().first()

        if existing:
            await db.execute(delete(VerificationToken).where(VerificationToken.id == existing.id))

        new_token = VerificationToken(
            email=email, token=token, expires=expires)
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)
        return new_token

    # Generate Password Reset Token
    async def generate_password_reset_token(self, email: str, db: AsyncSession) -> PasswordResetToken:
        token = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        result = await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.email == email)
        )
        existing = result.scalars().first()

        if existing:
            await db.execute(delete(PasswordResetToken).where(PasswordResetToken.id == existing.id))

        new_token = PasswordResetToken(
            email=email, token=token, expires=expires)
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)
        return new_token

    # Generate Two-Factor Token
    async def generate_two_factor_token(self, email: str, db: AsyncSession) -> TwoFactorToken:
        # Generates 6-digit token
        token = str(secrets.randbelow(899999) + 100000)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        result = await db.execute(
            select(TwoFactorToken).where(TwoFactorToken.email == email)
        )
        existing = result.scalars().first()

        if existing:
            await db.execute(delete(TwoFactorToken).where(TwoFactorToken.id == existing.id))

        new_token = TwoFactorToken(email=email, token=token, expires=expires)
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)
        return new_token

    # Get Verification Token by Token
    async def get_password_reset_token_by_token(self, token: str, db: AsyncSession) -> PasswordResetToken | None:
        result = await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.token == token)
        )
        password_reset_token = result.scalars().first()
        if password_reset_token and password_reset_token.expires > datetime.now(timezone.utc):
            return password_reset_token
        return None

    # Get Password Reset Token by Email
    async def get_password_reset_token_by_email(self, email: str, db: AsyncSession) -> PasswordResetToken | None:
        result = await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.email == email)
        )
        password_reset_token = result.scalars().first()
        if password_reset_token and password_reset_token.expires > datetime.now(timezone.utc):
            return password_reset_token
        return None

    # Get Two-Factor Confirmation by User ID

    async def get_two_factor_confirmation_by_user_id(self, user_id: str, db: AsyncSession) -> TwoFactorConfirmation | None:
        result = await db.execute(
            select(TwoFactorConfirmation).where(
                TwoFactorConfirmation.user_id == user_id)
        )
        two_factor_confirmation = result.scalars().first()
        if two_factor_confirmation and two_factor_confirmation.expires > datetime.now(timezone.utc):
            return two_factor_confirmation
        return None

    # Get Two-Factor Token by Token

    async def get_two_factor_token_by_token(self, token: str, db: AsyncSession) -> TwoFactorToken | None:
        result = await db.execute(
            select(TwoFactorToken).where(TwoFactorToken.token == token)
        )
        two_factor_token = result.scalars().first()
        if two_factor_token and two_factor_token.expires > datetime.now(timezone.utc):
            return two_factor_token
        return None

    # Get Two-Factor Token by Email
    async def get_two_factor_token_by_email(self, email: str, db: AsyncSession) -> TwoFactorToken | None:
        result = await db.execute(
            select(TwoFactorToken).where(TwoFactorToken.email == email)
        )
        two_factor_token = result.scalars().first()
        if two_factor_token and two_factor_token.expires > datetime.now(timezone.utc):
            return two_factor_token
        return None
    
    # enable two factor for User
    async def enable_two_factor_for_user(self, user_id: str, db: AsyncSession) -> TwoFactorConfirmation:
        # Check if the user already has two-factor enabled
        result = await db.execute(
            select(TwoFactorConfirmation).where(
                TwoFactorConfirmation.user_id == user_id)
        )
        existing = result.scalars().first()
        if existing:
            return existing
        else:
            new_confirmation = TwoFactorConfirmation(user_id=user_id)
            db.add(new_confirmation)
            await db.commit()
            await db.refresh(new_confirmation)
            return new_confirmation

    async def disable_two_factor_for_user(self, user_id: str, db: AsyncSession) -> None:
        # Check if the user has two-factor enabled
        result = await db.execute(
            select(TwoFactorConfirmation).where(
                TwoFactorConfirmation.user_id == user_id)
        )
        existing = result.scalars().first()
        if existing:
            await db.execute(delete(TwoFactorConfirmation).where(
                TwoFactorConfirmation.user_id == user_id)
            )
            await db.commit()
            return True
        else:
            return False

    # Get Verification Token by Email

    async def get_verification_token_by_email(self, email: str, db: AsyncSession) -> VerificationToken | None:
        result = await db.execute(
            select(VerificationToken).where(
                VerificationToken.email == email)
        )
        verification_token = result.scalars().first()
        if verification_token and verification_token.expires > datetime.now(timezone.utc):
            return verification_token
        return None

    # Get Verification Token by Token

    async def get_verification_token_by_token(self, token: str, db: AsyncSession) -> VerificationToken | None:
        result = await db.execute(
            select(VerificationToken).where(
                VerificationToken.token == token)
        )
        verification_token = result.scalars().first()
        if verification_token and verification_token.expires > datetime.now(timezone.utc):
            return verification_token
        return None
