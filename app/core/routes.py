from fastapi import APIRouter
from app.api.auth.routes.oauth_routes import oauth_router
from app.api.auth.routes.routes import auth_router
from app.api.auth.routes.user_routes import user_router

router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["authentication"])
router.include_router(oauth_router, prefix="/oauth", tags=["oauth"])
router.include_router(user_router, prefix="/user", tags=["user"])