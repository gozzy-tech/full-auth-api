from typing import Any, List
from fastapi import Depends, Request, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_get_db
from .models import User
from app.core.redis import token_in_blocklist
from .service import UserService
from .utils import decode_token
from .errors import (
    InvalidToken,
    RefreshTokenRequired,
    AccessTokenRequired,
    InsufficientPermission,
    AccountNotVerified,
)
import httpx

user_service = UserService()


class TokenBearer(HTTPBearer):
    def __init__(self, auto_error=True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        creds = await super().__call__(request)
        token = creds.credentials
        token_data = decode_token(token)
        if not self.token_valid(token):
            raise InvalidToken()
        if await token_in_blocklist(token_data["jti"]):
            raise InvalidToken()
        self.verify_token_data(token_data)
        return token_data

    def token_valid(self, token: str) -> bool:
        token_data = decode_token(token)
        return token_data is not None

    def verify_token_data(self, token_data):
        raise NotImplementedError(
            "Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and token_data["refresh"]:
            raise AccessTokenRequired()


class RefreshTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and not token_data["refresh"]:
            raise RefreshTokenRequired()


async def get_current_user(
    token_details: dict = Depends(AccessTokenBearer()),
    session: AsyncSession = Depends(async_get_db),
):
    user_email = token_details["user"]["email"]
    user = await user_service.get_user_by_email(user_email, session)
    return user


class RoleChecker:
    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> Any:
        if not current_user.is_verified:
            raise AccountNotVerified()
        if current_user.role in self.allowed_roles:
            return True

        raise InsufficientPermission()


async def verify_oauth_token(provider: str, oauth_token: str):
    if provider.lower() == "google":
        google_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={oauth_token}"
        async with httpx.AsyncClient() as client:
            response = await client.get(google_url)

        if response.status_code == 200:
            user_info = response.json()
            return {
                "email": user_info.get("email"),
                "first_name": user_info.get("given_name", ""),
                "last_name": user_info.get("family_name", ""),
                "avatar": user_info.get("picture", ""),
                "provider": "google",
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid Google token")

    elif provider.lower() == "facebook":
        # Use Facebook Graph API to fetch user details
        facebook_url = f"https://graph.facebook.com/me?fields=id,name,email&access_token={oauth_token}"
        async with httpx.AsyncClient() as client:
            response = await client.get(facebook_url)

        if response.status_code == 200:
            user_info = response.json()
            full_name = user_info.get("name", "").split()
            first_name = full_name[0] if full_name else ""
            last_name = full_name[1] if len(full_name) > 1 else ""
            avatar = user_info.get("picture", {}).get(
                "data", {}).get("url", ""),

            return {
                "email": user_info.get("email"),
                "first_name": first_name,
                "last_name": last_name,
                "provider": "facebook",
                "avatar": avatar
            }
        else:
            raise HTTPException(
                status_code=401, detail="Invalid Facebook token")

    else:
        raise HTTPException(
            status_code=400, detail="Unsupported OAuth provider")
