from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi import APIRouter


# Support nested template folders (auth, users, etc.)
templates = Jinja2Templates(directory="app/templates")

email_preview_router = APIRouter()


@email_preview_router.get("/", response_class=HTMLResponse)
async def preview_email(request: Request):
    return templates.TemplateResponse("auth/email_verfication.html", {
        "request": request,
        "token": "596853"
    })
