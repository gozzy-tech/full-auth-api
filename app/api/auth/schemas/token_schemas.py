import uuid
from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, field_serializer
import uuid
from datetime import datetime

# ----------------------------------------------------
#  Token Schemas
# ----------------------------------------------------

class VerificationTokenBase(BaseModel):
    email: EmailStr
    token: str
    expires: datetime


class VerificationTokenCreate(VerificationTokenBase): pass

class VerificationTokenOut(VerificationTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


class PasswordResetTokenBase(BaseModel):
    email: EmailStr
    token: str
    expires: datetime


class PasswordResetTokenCreate(PasswordResetTokenBase): pass

class PasswordResetTokenOut(PasswordResetTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


class TwoFactorTokenBase(BaseModel):
    email: EmailStr
    token: str
    expires: datetime


class TwoFactorTokenCreate(TwoFactorTokenBase): pass

class TwoFactorTokenOut(TwoFactorTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


class TwoFactorConfirmationBase(BaseModel):
    user_id: str


class TwoFactorConfirmationCreate(TwoFactorConfirmationBase): pass

class TwoFactorConfirmationOut(TwoFactorConfirmationBase):
    id: uuid.UUID

    class Config:
        from_attributes = True