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

    @field_serializer("expires")
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class VerificationTokenCreate(VerificationTokenBase): pass

class VerificationTokenOut(VerificationTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)
    



class PasswordResetTokenBase(BaseModel):
    email: EmailStr
    token: str
    expires: datetime

    @field_serializer("expires")
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class PasswordResetTokenCreate(PasswordResetTokenBase): pass

class PasswordResetTokenOut(PasswordResetTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)


class TwoFactorTokenBase(BaseModel):
    email: EmailStr
    token: str
    expires: datetime

    @field_serializer("expires")
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class TwoFactorTokenCreate(TwoFactorTokenBase): pass

class TwoFactorTokenOut(TwoFactorTokenBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)


class TwoFactorConfirmationBase(BaseModel):
    user_id: uuid.UUID

    @field_serializer("user_id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)



class TwoFactorConfirmationCreate(TwoFactorConfirmationBase): pass

class TwoFactorConfirmationOut(TwoFactorConfirmationBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)