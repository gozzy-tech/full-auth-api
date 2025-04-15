from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, status, BackgroundTasks, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_get_db
from app.core.mail import send_email, send_multiple_emails
from app.core.redis import token_in_blocklist, add_jti_to_blocklist

from .dependencies import (
    AccessTokenBearer,
    RefreshTokenBearer,
    RoleChecker,
    get_current_user,
    verify_oauth_token,
)
from .schemas import (
    OauthUserCreateModel,
    UserCreateModel,
    UserLoginModel,
    UserModel,
    EmailModel,
    PasswordResetRequestModel,
    PasswordResetConfirmModel,
    UserResponseModel,
    UserUpdateModel,
)
from .service import UserService
from .utils import (
    create_access_token,
    verify_password,
    generate_passwd_hash,
    create_url_safe_token,
    decode_url_safe_token,
)
from .errors import UserAlreadyExists, UserNotFound, InvalidCredentials, InvalidToken
from app.core.config import settings
from typing import List

auth_router = APIRouter()
user_service = UserService()
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


    token = create_url_safe_token({"email": email})
    print(token)

    link = f"http://{settings.DOMAIN}/api/v1/auth/verify/{token}"

    html = f"""
    <h1>Verify your Email</h1>
    <p>Please click this <a href="{link}">link</a> to verify your email</p>
    """

    emails = [email]

    subject = "Verify Your email"

    background_tasks.add_task(send_email, emails, subject, html, True)

    return JSONResponse(
        content={
            "message": "Account Created! Check email to verify your account",
            "user": UserModel.model_validate(new_user).model_dump(),
        },
        status_code=status.HTTP_201_CREATED
    )


@auth_router.get("/verify/{token}")
async def verify_user_account(token: str, session: AsyncSession = Depends(async_get_db)):
    token_data = decode_url_safe_token(token)
    user_email = token_data.get("email")
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


@auth_router.post("/login")
async def login_users(
    login_data: UserLoginModel, session: AsyncSession = Depends(async_get_db)
):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(email, session)

    if user is not None:
        password_valid = verify_password(password, user.password_hash)

        if password_valid:
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
                    "user": {"email": user.email, "uid": str(user.id)},
                },
                status_code=status.HTTP_200_OK
            )

    raise InvalidCredentials()


@auth_router.get("/refresh_token")
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    expiry_timestamp = token_details["exp"]

    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = create_access_token(user_data=token_details["user"])

        return JSONResponse(content={"access_token": new_access_token})

    raise InvalidToken


@auth_router.get("/profile", response_model=UserModel)
async def get_current_user(
    user=Depends(get_current_user), _: bool = Depends(role_checker)
):
    return user


@auth_router.get("/logout")
async def revoke_token(token_details: dict = Depends(AccessTokenBearer())):
    jti = token_details["jti"]

    await add_jti_to_blocklist(jti)

    return JSONResponse(
        content={"message": "Logged Out Successfully"}, status_code=status.HTTP_200_OK
    )


@auth_router.post("/password-reset-request")
async def password_reset_request(
    email_data: PasswordResetRequestModel,
    background_tasks: BackgroundTasks
    ):
    email = email_data.email
    token = create_url_safe_token({"email": email})

    link = f"http://{settings.DOMAIN}/api/v1/auth/password-reset-confirm/{token}"

    html_message = f"""
    <h1>Reset Your Password</h1>
    <p>Please click this <a href="{link}">link</a> to Reset Your Password</p>
    """
    subject = "Reset Your Password"
    background_tasks.add_task(send_email, [email], subject, html_message, True)

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
    new_password = passwords.new_password
    confirm_password = passwords.confirm_new_password

    if new_password != confirm_password:
        raise HTTPException(
            detail="Passwords do not match", status_code=status.HTTP_400_BAD_REQUEST
        )

    token_data = decode_url_safe_token(token)

    user_email = token_data.get("email")

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


@auth_router.get("/users", response_model=List[UserResponseModel])
async def fetch_users(
    role: str = Query("All", enum=["All", "admin", "teacher", "student"]),
    limit: int = Query(10, gt=0),
    offset: int = Query(0, ge=0),
    _: bool = Depends(admin_checker),
    session: AsyncSession = Depends(async_get_db)
):
    users = await user_service.get_users(role, limit, offset, session)
    return users


@auth_router.delete("/delete_user/{user_id}")
async def delete_user(
        user_id: UUID,
        _: UserModel = Depends(get_current_user),
        session: AsyncSession = Depends(async_get_db),
):
    deleted = await user_service.delete_user(user_id, session)

    if deleted:
        return JSONResponse(content={"message": "User deleted successfully"}, status_code=status.HTTP_200_OK)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found")


@auth_router.put("/update-user")
async def update_user(
    user_data: UserUpdateModel,
    user: UserModel = Depends(get_current_user),
    session: AsyncSession = Depends(async_get_db)
):
    # Check if the email already exists
    user_exists = await user_service.user_exists(user_data.email, session)

    if user_exists and user_data.email != user.email:
        raise HTTPException(
            detail="Email is already in use by another account.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    updated_user = await user_service.update_user(user, user_data.model_dump(), session)

    return JSONResponse(
        content={"message": "User information updated successfully",
                 "user": updated_user
                 },
        status_code=status.HTTP_200_OK
    )


@auth_router.post("/oauth-login")
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
