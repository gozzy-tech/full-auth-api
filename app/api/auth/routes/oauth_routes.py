from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth.services.token_service import TokenService
from app.core.database import async_get_db
from app.core.redis import add_oauth_code_to_blocklist, oauth_code_in_blocklist
from ..schemas.schemas import (
    GoogleUserCreateModel
)
from ..services.service import UserService
from ..utils import (
    create_auth_tokens,

)
from ..errors import UserNotFound, InvalidCredentials
from app.core.config import settings
from starlette.requests import Request
import uuid
from uuid import UUID
from fastapi.background import BackgroundTasks
from app.core.mail import send_email
from app.core.templates import templates

oauth_router = APIRouter()
user_service = UserService()
token_service = TokenService()

REFRESH_TOKEN_EXPIRY = settings.REFRESH_TOKEN_EXPIRY


oauth = OAuth()

oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
    }
)


# ------------------------------------------------
# OAuth Routes
# ------------------------------------------------

@oauth_router.get("/login/google")
async def login_via_google(request: Request):
    redirect_uri = request.url_for('auth_via_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@oauth_router.get("/callback/google")
async def auth_via_google(
    request: Request,
    session: AsyncSession = Depends(async_get_db)
):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token["userinfo"]
    except OAuthError:
        raise HTTPException(
            status_code=400,
            detail="OAuth flow failed. Try again."
        )

    user_data = GoogleUserCreateModel(**user_info)

    user = await user_service.get_user_by_email(user_data.email, session)

    if user:
        if user.login_provider == "email" and not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account exists but is not verified.",
            )
        elif user.login_provider == "email" and user.is_verified:
            user = await user_service.update_google_user(user, user_data, session)
        elif user.login_provider == "google":
            user = await user_service.update_google_user(user, user_data, session)
    else:
        user = await user_service.create_google_user(user_data, session)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User creation failed",
            )

    code = str(uuid.uuid4())
    await add_oauth_code_to_blocklist(code, str(user.id))

    return RedirectResponse(
        url=f"http://{settings.DOMAIN}/oauth_success?code={code}"
    )


# ----------------------------------------------
# create access and refresh tokens
# ----------------------------------------------
@oauth_router.get("/oauth_token/{code}")
async def create_oauth_token(
    code: str,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(async_get_db)
):
    user_id = await oauth_code_in_blocklist(code)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code",
        )
    user = await user_service.get_user_by_id(UUID(user_id), session)

    if not user:
        raise UserNotFound()

    if not user.is_verified:
        raise InvalidCredentials()

    if not user.is_oauth:
        raise InvalidCredentials()

    # Check if the user has 2FA enabled
    if user.two_factor_enabled:
        two_factor_token = await token_service.generate_two_factor_token(
            email=user.email, db=session
        )

        html = templates.get_template("auth/2fa_code.html").render(
            token=two_factor_token.token,
        )

        emails = [two_factor_token.email]
        subject = "2FA Code"
        background_tasks.add_task(send_email, emails, subject, html, True)

        return JSONResponse(
            content={
                "message": "2FA code sent to your email",
                "two_factor_required": True,
                "user": {"email": user.email, "uid": str(user.id)},
            },
            status_code=status.HTTP_202_ACCEPTED
        )

    access_token, refresh_token = create_auth_tokens(user)
    return JSONResponse(
        content={
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {"email": user.email, "id": str(user.id)},
        },
        status_code=status.HTTP_200_OK
    )
