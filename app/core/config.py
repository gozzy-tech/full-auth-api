from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    POSTGRES_URL: str = os.getenv("POSTGRES_URL")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = REDIS_URL

    # App settings
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "FastAPI App")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    DOMAIN: str = os.getenv("DOMAIN")

    # Auth Settings
    JWT_SECRET: str = os.getenv("JWT_SECRET", "secret")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "secret")

    # Mail and Resend Settings
    MAIL_USERNAME: str = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD: str = os.getenv("MAIL_PASSWORD")
    MAIL_FROM: str = os.getenv("MAIL_FROM")
    MAIL_SERVER: str = os.getenv("MAIL_SERVER")
    MAIL_FROM_NAME: str = os.getenv("MAIL_FROM_NAME")
    MAIL_PORT: int = os.getenv("MAIL_PORT", 587)
    RESEND_API_KEY: str = os.getenv("RESEND_API_KEY")
    RESEND_MAIL_FROM: str = os.getenv("RESEND_MAIL_FROM")

    class Config:
        env_file = ".env"  # Load from .env file
        env_file_encoding = "utf-8"


# Create an instance of settings
settings = Settings()
