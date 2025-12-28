from __future__ import annotations

import os
import smtplib
import logging
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Iterable

logger = logging.getLogger(__name__)

@dataclass
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    from_email: str = ""
    from_name: str = "Skyline Store"

    @property
    def ready(self) -> bool:
        return bool(self.host and self.port and self.username and self.password and self.from_email)

def load_smtp_config() -> SMTPConfig:
    return SMTPConfig(
        host=(os.getenv("SMTP_HOST") or "").strip(),
        port=int(os.getenv("SMTP_PORT") or "587"),
        username=(os.getenv("SMTP_USER") or "").strip(),
        password=(os.getenv("SMTP_PASS") or "").strip(),
        use_tls=(os.getenv("SMTP_TLS", "1").strip().lower() in {"1","true","yes","y","on"}),
        from_email=(os.getenv("SMTP_FROM_EMAIL") or "").strip(),
        from_name=(os.getenv("SMTP_FROM_NAME") or "Skyline Store").strip(),
    )

class EmailService:
    """
    Envío de emails por SMTP.
    - No rompe si no está configurado (modo dev): loguea y retorna False.
    """

    def __init__(self, cfg: Optional[SMTPConfig] = None):
        self.cfg = cfg or load_smtp_config()

    def ready(self) -> bool:
        return self.cfg.ready

    def send_html(self, to_email: str, subject: str, html: str, text: Optional[str] = None) -> bool:
        if not self.ready():
            logger.warning("EmailService no configurado (SMTP_*). No se envía: %s", subject)
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.cfg.from_name} <{self.cfg.from_email}>"
        msg["To"] = to_email

        if text:
            msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        try:
            with smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=20) as s:
                if self.cfg.use_tls:
                    s.starttls()
                s.login(self.cfg.username, self.cfg.password)
                s.sendmail(self.cfg.from_email, [to_email], msg.as_string())
            return True
        except Exception:
            logger.exception("Error enviando email a %s", to_email)
            return False

    def send_bulk_html(self, to_emails: Iterable[str], subject: str, html: str, text: Optional[str] = None) -> int:
        ok = 0
        for e in to_emails:
            if self.send_html(e, subject, html, text=text):
                ok += 1
        return ok
