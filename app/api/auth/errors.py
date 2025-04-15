from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from typing import Any, Callable

class AppException(Exception):
    """This is the base class for all bookly errors"""
    pass


class InvalidToken(AppException):
    """User has provided an invalid or expired token"""
    pass


class RevokedToken(AppException):
    """User has provided a token that has been revoked"""
    pass


class AccessTokenRequired(AppException):
    """User has provided a refresh token when an access token is needed"""
    pass


class RefreshTokenRequired(AppException):
    """User has provided an access token when a refresh token is needed"""
    pass


class UserAlreadyExists(AppException):
    """User has provided an email for a user who exists during sign up."""
    pass


class InvalidCredentials(AppException):
    """User has provided wrong email or password during log in."""
    pass


class InsufficientPermission(AppException):
    """User does not have the neccessary permissions to perform an action."""
    pass


class UserNotFound(AppException):
    """User Not found"""
    pass


class AccountNotVerified(AppException):
    """Account not yet verified"""
    pass


def create_exception_handler(
    status_code: int, initial_detail: Any
) -> Callable[[Request, Exception], JSONResponse]:
    """Creates a reusable exception handler."""
    
    async def exception_handler(request: Request, exc: Exception):  
        return JSONResponse(content=initial_detail, status_code=status_code)

    return exception_handler

def register_all_errors(app: FastAPI):
    """Registers all application-wide exception handlers."""
    
    exceptions = {
        UserAlreadyExists: (status.HTTP_403_FORBIDDEN, "User with email already exists", "user_exists"),
        UserNotFound: (status.HTTP_404_NOT_FOUND, "User not found", "user_not_found"),
        InvalidCredentials: (status.HTTP_400_BAD_REQUEST, "Invalid Email Or Password", "invalid_email_or_password"),
        InvalidToken: (status.HTTP_401_UNAUTHORIZED, "Token is invalid Or expired", "invalid_token", "Please get a new token"),
        RevokedToken: (status.HTTP_401_UNAUTHORIZED, "Token is invalid or has been revoked", "token_revoked", "Please get a new token"),
        AccessTokenRequired: (status.HTTP_401_UNAUTHORIZED, "Please provide a valid access token", "access_token_required"),
        RefreshTokenRequired: (status.HTTP_403_FORBIDDEN, "Please provide a valid refresh token", "refresh_token_required"),
        InsufficientPermission: (status.HTTP_401_UNAUTHORIZED, "You do not have enough permissions", "insufficient_permissions"),
        AccountNotVerified: (status.HTTP_403_FORBIDDEN, "Account Not verified", "account_not_verified", "Please check your email for verification details"),
    }

    # Register all exception handlers dynamically
    for exception, (code, message, error_code, *resolution) in exceptions.items():
        initial_detail = {"message": message, "error_code": error_code}
        if resolution:
            initial_detail["resolution"] = resolution[0]

        app.add_exception_handler(exception, create_exception_handler(status_code=code, initial_detail=initial_detail))

    @app.exception_handler(500)
    async def internal_server_error(request: Request, exc: Exception):
        return JSONResponse(
            content={"message": "Oops! Something went wrong", "error_code": "server_error"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        print(str(exc))
        return JSONResponse(
            content={"message": "Database error occurred", "error_code": "database_error"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
