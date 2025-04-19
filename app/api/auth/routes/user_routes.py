from uuid import UUID

from fastapi import APIRouter, Depends, status, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_get_db

from ..dependencies import (
    RoleChecker,
    get_current_user as get_current_user_dep,
)
from ..schemas.schemas import (
    UserModel,
    UserResponseModel,
    UserUpdateModel,
)
from ..services.service import UserService
from ..errors import UserAlreadyExists, UserNotFound, InvalidCredentials, InvalidToken
from typing import List

user_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(["admin", "user"])
admin_checker = RoleChecker(["admin"])

# --------------------------------------------------------------------
# Fetch all users
# --------------------------------------------------------------------

@user_router.get("/all", response_model=List[UserResponseModel])
async def fetch_users(
    role: str = Query("All", enum=["All", "admin", "user"]),
    limit: int = Query(10, gt=0),
    offset: int = Query(0, ge=0),
    _: bool = Depends(admin_checker),
    session: AsyncSession = Depends(async_get_db)
):
    users = await user_service.get_users(role, limit, offset, session)
    return users

# --------------------------------------------------------------------
# Fetch user by ID
# --------------------------------------------------------------------

@user_router.get("/profile", response_model=UserModel | None)
async def get_current_user(
    user: UserModel = Depends(get_current_user_dep)
):
    return user


# --------------------------------------------------------------------
# Update user information
# --------------------------------------------------------------------

@user_router.put("/update-user")
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
                 "user": UserUpdateModel.model_validate(updated_user).model_dump()
                 },
        status_code=status.HTTP_200_OK
    )

# --------------------------------------------------------------------
# Delete user
# --------------------------------------------------------------------

@user_router.delete("/delete_user/{user_id}")
async def delete_user(
        user_id: UUID,
        # _: UserModel = Depends(get_current_user),
        session: AsyncSession = Depends(async_get_db),
):
    deleted = await user_service.delete_user(user_id, session)

    if deleted:
        return JSONResponse(content={"message": "User deleted successfully"}, status_code=status.HTTP_200_OK)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found")
