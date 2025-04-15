from fastapi import APIRouter
from app.api.auth.routes import auth_router

router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["authentication"])