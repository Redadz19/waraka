import smtplib
from email.message import EmailMessage
from app.config import settings

def send_otp(email: str, code: str) -> None:
    if not all([settings.smtp_host, settings.smtp_username, settings.smtp_password]):
        raise RuntimeError("SMTP is not configured")
    msg = EmailMessage()
    msg["Subject"] = "WARAKA verification code"
    msg["From"] = settings.smtp_from
    msg["To"] = email
    msg.set_content(f"Your WARAKA verification code is: {code}\nIt expires in {settings.otp_ttl_seconds // 60} minutes.")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
        server.starttls()
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)
