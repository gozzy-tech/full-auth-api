from typing import Optional
import redis.asyncio as aioredis

from .config import settings

JTI_EXPIRY = 3600  # 1 hour

token_blocklist = aioredis.from_url(settings.REDIS_URL, decode_responses=True)


async def add_jti_to_blocklist(jti: str) -> None:
    await token_blocklist.set(name=jti, value="", ex=JTI_EXPIRY)


async def token_in_blocklist(jti: str) -> bool:
    jti = await token_blocklist.get(jti)

    return jti is not None


async def add_oauth_code_to_blocklist(code: str, user_id: str) -> None:
    await token_blocklist.set(name=code, value=user_id, ex=JTI_EXPIRY)


async def oauth_code_in_blocklist(code: str) -> Optional[str]:
    user_id = await token_blocklist.get(code)
    if user_id:
        await token_blocklist.delete(code)
        return user_id
    return None
