from fastapi import APIRouter
from app.api.auth.routes.routes import auth_router
from app.api.auth.routes.user_routes import user_router

router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["authentication"])
router.include_router(user_router, prefix="/users", tags=["users"])