from fastapi import FastAPI
from app.api.auth.errors import register_all_errors
from app.core.config import settings
from app.core.middleware import register_middleware
from app.core.routes import router as main_router
from fastapi.staticfiles import StaticFiles

description = """
A REST API Authentication and Authorization with FastAPI, Redis, PostgreSQL, and Celery.
This API provides endpoints for user registration, login, password reset, and email verification.

"""

app = FastAPI(title=settings.PROJECT_NAME,
              description=description,
              version=settings.VERSION,
              contact={
                  "name": "Full Authentication",
                  "url": "https://fullauthentication.com",
                  "email": "chiagoziendukwe@gmail.com",
              },
              )

version_prefix = f"/api/v1"
app.include_router(main_router, prefix=version_prefix)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

register_all_errors(app)
register_middleware(app)


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Full Authentication API"}

