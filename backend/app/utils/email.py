import smtplib
from email.message import EmailMessage

def send_email(to: str, subject: str, content: str, smtp_server: str, smtp_port: int, username: str, password: str):
    msg = EmailMessage()
    msg["From"] = username
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(content)
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(msg)