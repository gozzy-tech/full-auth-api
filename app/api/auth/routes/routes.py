from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, status, BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth.schemas.token_schemas import TwoFactorTokenCreate
from app.api.auth.services.token_service import TokenService
from app.core.database import async_get_db
from app.core.mail import send_email, send_multiple_emails
from app.core.redis import add_jti_to_blocklist

from ..dependencies import (
    AccessTokenBearer,
    RefreshTokenBearer,
    RoleChecker,
    get_current_user,
)
from ..schemas.schemas import (
    UserCreateModel,
    UserLoginModel,
    UserModel,
    EmailModel,
    PasswordResetRequestModel,
    PasswordResetConfirmModel,
)
from ..services.service import UserService
from ..utils import (
    create_access_token,
    verify_password,
    generate_passwd_hash,
)
from ..errors import UserAlreadyExists, UserNotFound, InvalidCredentials, InvalidToken
from app.core.config import settings
from typing import List

auth_router = APIRouter()
user_service = UserService()
token_service = TokenService()
role_checker = RoleChecker(["admin", "user"])
admin_checker = RoleChecker(["admin"])


REFRESH_TOKEN_EXPIRY = 2


# Bearer Token
@auth_router.post("/send_mail")
async def send_mail(emails: EmailModel):
    emails = emails.addresses

    html = "<h1>Welcome to the app</h1>"
    subject = "Welcome to our app"

    # Send email using Resend
    BackgroundTasks(send_multiple_emails, emails, subject, html)

    return {"message": "Email sent successfully"}


# ------------------------------------------------
# Auth Routes
# ------------------------------------------------

@auth_router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_user_Account(
    user_data: UserCreateModel,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(async_get_db),
):
    """
    Create user account using email, username, first_name, last_name
    params:
        user_data: UserCreateModel
    """
    email = user_data.email

    user_exists = await user_service.user_exists(email, session)

    if user_exists:
        raise UserAlreadyExists()

    new_user = await user_service.create_user(user_data, session)

    token_data = await token_service.generate_verification_token(
        email=email,
        db=session,
    )

    link = f"http://{settings.DOMAIN}/verify-email?token={token_data.token}"
    html = f"""
    <h1>Verify your Email</h1>
    <p>Please click this <a href="{link}">link</a> to verify your email</p>
    """
    emails = [token_data.email]
    subject = "Verify Your email"
    background_tasks.add_task(send_email, emails, subject, html, True)

    return JSONResponse(
        content={
            "message": "Account Created! Check email to verify your account",
            "user": UserModel.model_validate(new_user).model_dump(),
        },
        status_code=status.HTTP_201_CREATED
    )


@auth_router.post("/login")
async def login_users(
    login_data: UserLoginModel,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(async_get_db),
):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(email, session)

    if user and verify_password(password, user.password_hash):

        # check if user email is verified
        if not user.is_verified:
            raise JSONResponse(
                content={
                    "message": "Email not verified",
                    "user": {"email": user.email, "uid": str(user.id)},
                },
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        # Check if user is 2FA enabled
        if user.two_factor_enabled:
            two_factor_token = await token_service.generate_two_factor_token(
                email=user.email, db=session
            )

            html = f"""
            <h1>2FA Code</h1>
            <p>
                Your 2FA code is: <strong>{two_factor_token.token}</strong>
                <br>
                This code is valid for 5 minutes.
            </p>
            <p>
                If you did not request this code, please ignore this email.
            </p>
            """
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

        # If 2FA not enabled, proceed with login
        access_token = create_access_token(
            user_data={
                "email": user.email,
                "user_uid": str(user.id),
                "role": user.role,
            }
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

    raise InvalidCredentials()


@auth_router.get("/verify/{token}")
async def verify_user_account(token: str, session: AsyncSession = Depends(async_get_db)):
    """
    Verify user account using token
    params:
        token: str
    """
    token_data = await token_service.get_verification_token_by_token(token, session)
    user_email = token_data.email
    if user_email:
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()

        await user_service.update_user(user, {"is_verified": True}, session)

        return JSONResponse(
            content={"message": "Account verified successfully"},
            status_code=status.HTTP_200_OK,
        )

    return JSONResponse(
        content={"message": "Error occured during verification"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


@auth_router.get("/refresh_token")
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    expiry_timestamp = token_details["exp"]

    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = create_access_token(user_data=token_details["user"])

        return JSONResponse(content={"access_token": new_access_token})

    raise InvalidToken


@auth_router.get("/logout")
async def revoke_token(token_details: dict = Depends(AccessTokenBearer())):
    """
    Revoke the access token and refresh token
    params:
        token_details: dict
    """
    jti = token_details["jti"]
    await add_jti_to_blocklist(jti)
    return JSONResponse(
        content={"message": "Logged Out Successfully"}, status_code=status.HTTP_200_OK
    )


@auth_router.post("/password-reset-request")
async def password_reset_request(
    email_data: PasswordResetRequestModel,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(async_get_db),
):
    email = email_data.email
    token_data = await token_service.generate_password_reset_token(email, session)
    if not token_data:
        raise HTTPException(
            detail="Invalid email address", status_code=status.HTTP_400_BAD_REQUEST
        )

    link = f"http://{settings.DOMAIN}/reset-password?token={token_data.token}"

    html_message = f"""
    <h1>Reset Your Password</h1>
    <p>Please click this <a href="{link}">link</a> to Reset Your Password</p>
    """
    subject = "Reset Your Password"
    background_tasks.add_task(
        send_email, [token_data.email], subject, html_message, True)

    return JSONResponse(
        content={
            "message": "Please check your email for instructions to reset your password",
        },
        status_code=status.HTTP_200_OK,
    )


@auth_router.post("/password-reset-confirm/{token}")
async def reset_account_password(
    token: str,
    passwords: PasswordResetConfirmModel,
    session: AsyncSession = Depends(async_get_db),
):
    """
    Reset user password using token
    params:
        token: str
        passwords: PasswordResetConfirmModel
    """
    new_password = passwords.new_password
    confirm_password = passwords.confirm_new_password

    if new_password != confirm_password:
        raise HTTPException(
            detail="Passwords do not match", status_code=status.HTTP_400_BAD_REQUEST
        )

    token_data = await token_service.get_password_reset_token_by_token(token, session)
    user_email = token_data.email

    if user_email:
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()

        passwd_hash = generate_passwd_hash(new_password)
        await user_service.update_user(user, {"password_hash": passwd_hash}, session)

        return JSONResponse(
            content={"message": "Password reset Successfully"},
            status_code=status.HTTP_200_OK,
        )

    return JSONResponse(
        content={"message": "Error occured during password reset."},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


# ------------------------------------------------
# 2FA Routes
# ------------------------------------------------
@auth_router.get("/enable-2FA")
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


@auth_router.post("/verify-2FA-code/{token}", status_code=status.HTTP_200_OK)
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

    if user.two_factor_enabled:
        raise HTTPException(
            detail="2FA is already enabled.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    access_token = create_access_token(
        user_data={
            "email": user.email,
            "user_uid": str(user.id),
            "role": user.role,
        }
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


@auth_router.get("/disable-2FA")
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
