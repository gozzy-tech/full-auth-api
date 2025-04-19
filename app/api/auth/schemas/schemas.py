import email
import uuid
from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, field_serializer, HttpUrl
import uuid
from datetime import datetime


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


class UserCreateModel(BaseModel):
    """
    User registration model
    """
    first_name: str = Field(max_length=25)
    last_name: str = Field(max_length=25)
    email: str = Field(max_length=40)
    password: str = Field(min_length=6)

    model_config = {
        "json_schema_extra": {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe123@co.com",
                "password": "testpass123",
            }
        }
    }


class GoogleUserCreateModel(BaseModel):
    """
    Google user registration model
    """
    sub: str  # Google user ID
    name: str
    given_name: str
    family_name: str
    picture: HttpUrl
    email: EmailStr
    email_verified: bool
    locale: Optional[str] = None  # ← Make this optional


class UserResponseModel(BaseModel):
    id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr  # Ensures email validation
    phone: Optional[str] = None
    avatar: Optional[str] = None
    gender: Optional[str] = None
    role: Role = Role.USER

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)


class UserModel(BaseModel):
    id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr  # Ensures email validation
    phone: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    password_hash: Optional[str] = Field(exclude=True)
    avatar: Optional[str] = None
    bio: Optional[str] = None
    gender: Optional[str] = None
    role: Role = Role.USER
    is_verified: bool = False
    two_factor_enabled: bool = False
    is_oauth: bool = False
    created_at: datetime

    @field_serializer("id")
    def serialize_uuid(self, value: uuid.UUID) -> str:
        return str(value)
    
    @field_serializer("created_at")
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()

    class Config:
        from_attributes = True  # Enables ORM compatibility for SQLAlchemy integration


class UserUpdateModel(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None  # Make email optional
    phone: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    avatar: Optional[str] = None
    bio: Optional[str] = None
    gender: Optional[str] = None

    class Config:
        from_attributes = True


class UserLoginModel(BaseModel):
    email: str = Field(max_length=40)
    password: str = Field(min_length=6)


class EmailModel(BaseModel):
    addresses: List[str]


class TokenRequestModel(BaseModel):
    email: str



class PasswordResetConfirmModel(BaseModel):
    new_password: str
    confirm_new_password: str

class PasswordResetModel(BaseModel):
    new_password: str
    confirm_new_password: str
    old_password: str

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "new_password": "newpassword123",
                "confirm_new_password": "newpassword123",
                "old_password": "oldpassword123"
            }
        }



