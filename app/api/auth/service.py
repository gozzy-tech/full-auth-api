from uuid import UUID
from fastapi import Depends
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_get_db
from .models import User
from .schemas import OauthUserCreateModel, UserCreateModel
from .utils import generate_passwd_hash
from typing import Optional, List


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
    
    async def create_oauth_user(self, user_data: OauthUserCreateModel, session: AsyncSession = Depends(async_get_db)) -> User:
        user_data_dict = user_data.model_dump()
        new_user = User(**user_data_dict)
        session.add(new_user)
        await session.commit()
        # Ensure we return the updated instance
        await session.refresh(new_user)
        return new_user

    async def update_user(self, user: User, user_data: dict, session: AsyncSession = Depends(async_get_db)) -> User:
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
        return True  # Successfully deleted
