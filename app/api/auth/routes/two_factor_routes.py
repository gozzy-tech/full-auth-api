from datetime import timedelta
from fastapi import APIRouter, Depends, status, BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth.routes.oauth_routes import REFRESH_TOKEN_EXPIRY
from app.api.auth.services.token_service import TokenService
from app.core.database import async_get_db
from app.core.mail import send_email

from ..dependencies import (
    RoleChecker,
    get_current_user,
)
from ..schemas.schemas import (
    TokenRequestModel,
    UserModel,

)
from ..services.service import UserService
from ..utils import (
    create_access_token,
    create_auth_tokens,
)
from ..errors import UserNotFound

twoFA_router = APIRouter()
user_service = UserService()
token_service = TokenService()
role_checker = RoleChecker(["admin", "user"])
admin_checker = RoleChecker(["admin"])


# --------------------------------------------------------------------
# Enable 2FA for user
# --------------------------------------------------------------------
@twoFA_router.get("/enable-2FA")
async def enable_2fa(
    user: UserModel = Depends(get_current_user),
    session: AsyncSession = Depends(async_get_db)
):
    """
    Enable 2FA for user
    params:
        user: UserModel
    """
    user_2fa = await token_service.enable_two_factor_for_user(user.id, session)
    if not user_2fa:
        raise HTTPException(
            detail="Error enabling 2FA", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    await user_service.update_user(user, {"two_factor_enabled": True}, session)
    return JSONResponse(
        content={
            "message": "2FA enabled successfully",
        },
        status_code=status.HTTP_200_OK,
    )

# --------------------------------------------------------------------
# Generate 2FA token
# --------------------------------------------------------------------

@twoFA_router.get("/verify-2FA-code/{token}", status_code=status.HTTP_200_OK)
async def verify_2fa_code(
    token: str,
    session: AsyncSession = Depends(async_get_db)
):
    """
    Verify the 2FA token and enable 2FA for the user.
    """
    token_obj = await token_service.get_two_factor_token_by_token(token, session)

    if not token_obj:
        raise HTTPException(
            detail="Invalid or expired token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    user = await user_service.get_user_by_email(token_obj.email, session)
    if not user:
        raise UserNotFound()

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

# --------------------------------------------------------------------
# Resend 2FA code
# --------------------------------------------------------------------


@twoFA_router.post("/resend-2FA-code")
async def resend_2fa_code(
    email_data: TokenRequestModel,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(async_get_db)
):
    """
    Resend the 2FA code to the user's email.
    params:
        user: UserModel
    """
    token_obj = await token_service.generate_two_factor_token(
        email=email_data.email, db=session
    )
    if not token_obj:
        raise JSONResponse(
            content={"message": "Error generating 2FA token"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    html = f"""
    <h1>2FA Code</h1>
    <p>
        Your 2FA code is: <strong>{token_obj.token}</strong>
        <br>
        This code is valid for 1 hour.
    </p>
    <p>
        If you did not request this code, please ignore this email.
    </p>
    """
    emails = [token_obj.email]
    subject = "2FA Code"
    background_tasks.add_task(send_email, emails, subject, html, True)
    return JSONResponse(
        content={
            "message": "2FA code resent to your email",
        },
        status_code=status.HTTP_200_OK
    )

# --------------------------------------------------------------------
# Disable 2FA for user
# --------------------------------------------------------------------


@twoFA_router.get("/disable-2FA")
async def disable_2fa(
    user: UserModel = Depends(get_current_user),
    session: AsyncSession = Depends(async_get_db)
):
    """
    Disable 2FA for user
    params:
        user: UserModel
    """
    disabled = await token_service.disable_two_factor_for_user(user.id, session)
    if not disabled:
        raise HTTPException(
            detail="Error disabling 2FA", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    await user_service.update_user(user, {"two_factor_enabled": False}, session)
    # Invalidate the 2FA token
    token_obj = await token_service.get_two_factor_token_by_email(user.email, session)
    if token_obj:
        await session.delete(token_obj)
        await session.commit()
        await session.refresh(token_obj)

    return JSONResponse(
        content={"message": "2FA disabled successfully"},
        status_code=status.HTTP_200_OK,
    )
