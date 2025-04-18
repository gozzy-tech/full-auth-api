from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, status, BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth.services.token_service import TokenService
from app.core.database import async_get_db

from ..dependencies import (verify_oauth_token,
)
from ..schemas.schemas import (
    OauthUserCreateModel,
)
from ..services.service import UserService
from ..utils import (
    create_access_token,
)
from ..errors import UserAlreadyExists, UserNotFound, InvalidCredentials, InvalidToken
from app.core.config import settings
from typing import List

oauth_router = APIRouter()
user_service = UserService()
token_service = TokenService()

REFRESH_TOKEN_EXPIRY = 2

# ------------------------------------------------
# OAuth Routes
# ------------------------------------------------

@oauth_router.post("/oauth-login")
async def oauth_login(
    oauth_token: str,
    provider: str,
    session: AsyncSession = Depends(async_get_db)
):
    user_data = await verify_oauth_token(oauth_token, provider)

    if not user_data:
        raise InvalidToken()

    user = await user_service.get_user_by_email(user_data["email"], session)

    if not user:
        # If user doesn't exist, create a new one
        new_user_data = OauthUserCreateModel(
            email=user_data["email"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            is_verified=True,
            is_oauth=True,
            login_provider=provider,
            avatar=user_data["avatar"]
        )
        user = await user_service.create_oauth_user(new_user_data, session)

    # Generate and return access and refresh tokens
    access_token = create_access_token(
        user_data={"email": user.email, "user_uid": str(
            user.id), "role": user.role}
    )

    refresh_token = create_access_token(
        user_data={"email": user.email, "user_uid": str(user.id)},
        refresh=True,
        expiry=timedelta(days=REFRESH_TOKEN_EXPIRY),
    )

    return JSONResponse(
        content={
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {"email": user.email, "id": str(user.id)},
        },
        status_code=status.HTTP_200_OK
    )
