from app.core.config import settings
from pathlib import Path
import resend
from typing import List

BASE_DIR = Path(__file__).resolve().parent

# Resend Email API Key
resend.api_key = settings.RESEND_API_KEY


def send_email(
    recipients: List[str], subject: str, body: str, use_resend: bool = False
):
    """
    Sends an email using either FastAPI-Mail or Resend.

    - `recipients`: List of recipient emails
    - `subject`: Email subject
    - `body`: HTML body content
    - `use_resend`: If `True`, send via Resend, else use FastAPI-Mail
    """
    params: resend.Emails.SendParams = {
        "from": settings.RESEND_MAIL_FROM, 
        "to": recipients,
        "subject": subject,
        "html": body,
    }
    try:
        email_response = resend.Emails.send(params)
        return {"status": "success", "provider": "resend", "response": email_response}
    except Exception as e:
        print(str(e))
        return {"status": "error", "provider": "resend", "error": str(e)}




def send_multiple_emails(recipients: List[str], subject: str, body: str):
    """
    Send multiple emails using Resend only
    - `recipients`: List of recipient emails
    - `subject`: Email subject
    - `body`: HTML body content
    """
    params: List[resend.Emails.SendParams] = []
    for recipient_email in recipients:
        params.append({
            "from": settings.RESEND_MAIL_FROM,
            "to": [recipient_email],
            "subject": subject,
            "html": body,
        })
    resend.Batch.send(params)
