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



def send_license(email: str, serial: str) -> None:
    if not all([settings.smtp_host, settings.smtp_username, settings.smtp_password]):
        raise RuntimeError("SMTP is not configured")
    msg = EmailMessage()
    msg["Subject"] = "Your WARAKA lifetime license"
    msg["From"] = settings.smtp_from
    msg["To"] = email
    msg.set_content(
        "Thank you for purchasing WARAKA.\n\n"
        f"Your lifetime license serial is: {serial}\n\n"
        "This is a one-time purchase license. It supports up to three devices. "
        "Online verification is required periodically; offline use is supported "
        "for up to 14 days. Keep this serial in a safe place.\n"
    )
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
        server.starttls()
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)
