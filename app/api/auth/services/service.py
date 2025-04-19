from uuid import UUID
from fastapi import Depends
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_get_db
from ..models import User
from ..schemas.schemas import GoogleUserCreateModel, UserCreateModel
from ..utils import generate_passwd_hash
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select


class UserService:
    async def get_users(
        self,
        role: str = "All",
        limit: int = 10,
        offset: int = 0,
        session: AsyncSession = Depends(async_get_db)
    ) -> List[User]:
        """Retrieve users based on role with pagination"""
        statement = select(User)

        if role.lower() in ["student", "teacher"]:
            statement = statement.where(User.role == role.lower())

        statement = statement.limit(limit).offset(offset)

        result = await session.execute(statement)
        return result.scalars().all()

    async def get_user_by_email(self, email: str, session: AsyncSession = Depends(async_get_db)) -> Optional[User]:
        statement = select(User).where(User.email == email)
        result = await session.execute(statement)
        return result.scalars().first()

    async def get_user_by_id(self, user_id: UUID, session: AsyncSession = Depends(async_get_db)) -> Optional[User]:
        statement = select(User).where(User.id == user_id)
        result = await session.execute(statement)
        return result.scalars().first()

    async def user_exists(self, email: str, session: AsyncSession = Depends(async_get_db)) -> bool:
        return await self.get_user_by_email(email, session) is not None

    async def create_user(self, user_data: UserCreateModel, session: AsyncSession = Depends(async_get_db)) -> User:
        user_data_dict = user_data.model_dump()
        user_data_dict["password_hash"] = generate_passwd_hash(
            user_data_dict.pop("password"))
        new_user = User(**user_data_dict)
        session.add(new_user)
        await session.commit()
        # Ensure we return the updated instance
        await session.refresh(new_user)
        return new_user

    async def update_user(
        self,
        user: User,
        user_data: dict,
        session: AsyncSession = Depends(async_get_db)
    ) -> User:
        # Avoid updating email if it's None
        if "email" in user_data and user_data["email"] is None:
            user_data.pop("email")

        # Check if email is being changed
        if "email" in user_data and user_data["email"] != user.email:
            user.is_verified = False

        # Apply all updates
        for key, value in user_data.items():
            setattr(user, key, value)

        await session.commit()
        await session.refresh(user)  # Refresh instance after commit
        return user

    async def delete_user(self, user_id: UUID, session: AsyncSession = Depends(async_get_db)) -> bool:
        statement = select(User).where(User.id == user_id)
        result = await session.execute(statement)
        user = result.scalars().first()

        if not user:
            return False  # User not found

        await session.delete(user)
        await session.commit()
        return True  # User deleted successfully

    async def create_google_user(self, user_data: GoogleUserCreateModel, session: AsyncSession = Depends(async_get_db)) -> User:
        user_data_dict = user_data.model_dump()
        new_user = User(
            first_name=user_data_dict["given_name"],
            last_name=user_data_dict["family_name"],
            email=user_data_dict["email"],
            is_verified=user_data_dict["email_verified"],
            role="user",  # Default role
            avatar=str(user_data_dict.get("picture")
                       ) if user_data_dict.get("picture") else None,
            is_oauth=True,
            login_provider="google",
        )
        session.add(new_user)
        await session.commit()
        # Ensure we return the updated instance
        await session.refresh(new_user)
        return new_user

    async def update_google_user(
        self,
        user: User,
        user_data: GoogleUserCreateModel,
        session: AsyncSession = Depends(async_get_db)
    ) -> User:
        user_data_dict = user_data.model_dump()
        # Update other fields
        user.email = user_data_dict.get("email", user.email)
        user.first_name = user_data_dict.get("given_name", user.first_name)
        user.last_name = user_data_dict.get("family_name", user.last_name)
        user.avatar = str(user_data_dict.get("picture")) if user_data_dict.get(
            "picture") else user.avatar
        user.login_provider = "google"
        user.is_oauth = True
        user.is_verified = user_data_dict.get(
            "email_verified", user.is_verified)

        # Commit the updates
        session.add(user)
        await session.commit()
        await session.refresh(user)

        return user
