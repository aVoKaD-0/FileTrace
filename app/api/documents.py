from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter(prefix="/documents", tags=["documents"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/user_agreement", response_class=HTMLResponse)
async def user_agreement(request: Request):
    return templates.TemplateResponse("user_agreement.html", {"request": request})
