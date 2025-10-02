import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config_utils import ConfigMapper


def send_email(to_email: str, subject: str, body: str) -> None:
    """
    Sends an email using SMTP with TLS encryption.

    Args:
        to_email (str): Recipient's email address.
        subject (str): Subject of the email.
        body (str): HTML content of the email body.

    Raises:
        Exception: If sending the email fails.
    """
    settings = ConfigMapper.get()
    msg = MIMEMultipart()
    msg["From"] = settings.SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "html"))

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, to_email, msg.as_string())
            print(f"[Notification] Email sent to {to_email}")
    except Exception as e:
        print(f"[Notification Error] Failed to send email: {e}")
