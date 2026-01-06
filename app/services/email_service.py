from __future__ import annotations

import os
import re
import ssl
import time
import smtplib
import logging
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, List, Tuple, Union

from email.message import EmailMessage

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _as_bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    s = v.strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _as_int(v: Optional[str], default: int) -> int:
    if v is None:
        return default
    try:
        n = int(str(v).strip())
        return n if n > 0 else default
    except Exception:
        return default


def _clean_header(value: str) -> str:
    # evita header injection
    if "\n" in value or "\r" in value:
        return " ".join(value.replace("\r", " ").replace("\n", " ").split())
    return value.strip()


def _normalize_email_list(x: Union[str, Sequence[str], None]) -> List[str]:
    if not x:
        return []
    if isinstance(x, str):
        parts = [p.strip() for p in x.split(",")]
        return [p for p in parts if p]
    out: List[str] = []
    for v in x:
        if v:
            out.append(str(v).strip())
    return [p for p in out if p]


def _is_valid_email(addr: str) -> bool:
    a = (addr or "").strip()
    if not a or len(a) > 320:
        return False
    return bool(_EMAIL_RE.match(a))


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str

    # STARTTLS (587) o SSL directo (465)
    use_tls: bool = True
    use_ssl: bool = False

    from_email: str = ""
    from_name: str = "Skyline Store"

    timeout: int = 20
    retries: int = 1
    retry_sleep_sec: float = 0.6

    @property
    def ready(self) -> bool:
        return bool(
            self.host
            and self.port
            and self.username
            and self.password
            and self.from_email
            and _is_valid_email(self.from_email)
        )


def load_smtp_config() -> SMTPConfig:
    """
    ENV soportadas:
      SMTP_HOST
      SMTP_PORT (default 587)
      SMTP_USER
      SMTP_PASS
      SMTP_TLS (default 1)   -> STARTTLS
      SMTP_USE_SSL (default 0) -> SMTP_SSL 465
      SMTP_FROM_EMAIL (o SMTP_FROM)
      SMTP_FROM_NAME
      SMTP_TIMEOUT (default 20)
      SMTP_RETRIES (default 1)
      SMTP_RETRY_SLEEP (default 0.6)
    """
    host = (os.getenv("SMTP_HOST") or "").strip()
    port = _as_int(os.getenv("SMTP_PORT"), 587)

    username = (os.getenv("SMTP_USER") or "").strip()
    password = (os.getenv("SMTP_PASS") or "").strip()

    # compatibilidad: SMTP_FROM o SMTP_FROM_EMAIL
    from_email = (os.getenv("SMTP_FROM_EMAIL") or os.getenv("SMTP_FROM") or "").strip()
    from_name = (os.getenv("SMTP_FROM_NAME") or "Skyline Store").strip()

    use_ssl = _as_bool(os.getenv("SMTP_USE_SSL"), False)
    use_tls = _as_bool(os.getenv("SMTP_TLS"), True)

    # Si SSL está activo, normalmente no se usa STARTTLS
    if use_ssl:
        use_tls = False
        if os.getenv("SMTP_PORT") is None:
            port = 465

    timeout = _as_int(os.getenv("SMTP_TIMEOUT"), 20)
    retries = _as_int(os.getenv("SMTP_RETRIES"), 1)
    retry_sleep_sec = float(os.getenv("SMTP_RETRY_SLEEP") or "0.6")

    return SMTPConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        use_tls=use_tls,
        use_ssl=use_ssl,
        from_email=from_email,
        from_name=from_name,
        timeout=timeout,
        retries=max(0, retries),
        retry_sleep_sec=max(0.0, retry_sleep_sec),
    )


class EmailService:
    """
    EmailService — SMTP seguro y robusto (PRO).
    - No rompe si no está configurado: log + retorna False/0.
    - STARTTLS (587) o SSL directo (465).
    - Anti header injection.
    - Validación mínima de emails.
    - Bulk opcional con conexión reutilizada.
    """

    def __init__(self, cfg: Optional[SMTPConfig] = None):
        self.cfg = cfg or load_smtp_config()
        self._smtp: Optional[smtplib.SMTP] = None

    def ready(self) -> bool:
        return self.cfg.ready

    # ---------- conexión ----------
    def _connect(self) -> smtplib.SMTP:
        if self.cfg.use_ssl:
            ctx = ssl.create_default_context()
            s: smtplib.SMTP = smtplib.SMTP_SSL(
                self.cfg.host, self.cfg.port, timeout=self.cfg.timeout, context=ctx
            )
        else:
            s = smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=self.cfg.timeout)

        # handshake
        try:
            s.ehlo()
        except Exception:
            # algunos servers ignoran ehlo pre-TLS; no fallamos por eso
            pass

        if self.cfg.use_tls and not self.cfg.use_ssl:
            ctx = ssl.create_default_context()
            s.starttls(context=ctx)
            try:
                s.ehlo()
            except Exception:
                pass

        if self.cfg.username and self.cfg.password:
            s.login(self.cfg.username, self.cfg.password)

        return s

    def _get_or_open(self) -> smtplib.SMTP:
        if self._smtp is not None:
            return self._smtp
        self._smtp = self._connect()
        return self._smtp

    def close(self) -> None:
        if self._smtp is None:
            return
        try:
            self._smtp.quit()
        except Exception:
            try:
                self._smtp.close()
            except Exception:
                pass
        finally:
            self._smtp = None

    # ---------- helpers ----------
    def _build_message(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
        *,
        cc: Union[str, Sequence[str], None] = None,
        bcc: Union[str, Sequence[str], None] = None,
        reply_to: Optional[str] = None,
    ) -> Tuple[EmailMessage, List[str]]:
        to_email = (to_email or "").strip()
        if not _is_valid_email(to_email):
            raise ValueError(f"Email destino inválido: {to_email!r}")

        cc_list = [e for e in _normalize_email_list(cc) if _is_valid_email(e)]
        bcc_list = [e for e in _normalize_email_list(bcc) if _is_valid_email(e)]

        msg = EmailMessage()
        msg["Subject"] = _clean_header(subject or "")
        msg["From"] = _clean_header(f"{self.cfg.from_name} <{self.cfg.from_email}>")
        msg["To"] = _clean_header(to_email)

        if cc_list:
            msg["Cc"] = _clean_header(", ".join(cc_list))
        if reply_to and _is_valid_email(reply_to):
            msg["Reply-To"] = _clean_header(reply_to)

        # Plain fallback (si no te pasan text)
        plain = (text or "").strip()
        if not plain:
            # muy simple: evita enviar vacío
            plain = (
                "Hola! Te compartimos una actualización de tu pedido en Skyline Store."
            )

        msg.set_content(plain, subtype="plain", charset="utf-8")
        msg.add_alternative(html or "", subtype="html", charset="utf-8")

        recipients = [to_email] + cc_list + bcc_list
        return msg, recipients

    # ---------- API pública ----------
    def send_html(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
        *,
        cc: Union[str, Sequence[str], None] = None,
        bcc: Union[str, Sequence[str], None] = None,
        reply_to: Optional[str] = None,
        reuse_connection: bool = False,
    ) -> bool:
        if not self.ready():
            logger.warning(
                "EmailService no configurado (SMTP_*). No se envía: %s", subject
            )
            return False

        try:
            msg, recipients = self._build_message(
                to_email, subject, html, text, cc=cc, bcc=bcc, reply_to=reply_to
            )
        except Exception as e:
            logger.warning("Email inválido o datos inválidos. No se envía. Err=%s", e)
            return False

        last_err: Optional[Exception] = None
        attempts = 1 + max(0, self.cfg.retries)

        for i in range(attempts):
            try:
                smtp = self._get_or_open() if reuse_connection else self._connect()
                smtp.send_message(
                    msg, from_addr=self.cfg.from_email, to_addrs=recipients
                )
                if not reuse_connection:
                    try:
                        smtp.quit()
                    except Exception:
                        try:
                            smtp.close()
                        except Exception:
                            pass
                return True
            except Exception as e:
                last_err = e
                logger.exception(
                    "Error enviando email (try %s/%s) a %s", i + 1, attempts, to_email
                )
                # si era conexión persistente, la cerramos para reintentar limpio
                if reuse_connection:
                    self.close()
                if i < attempts - 1:
                    time.sleep(self.cfg.retry_sleep_sec)

        if last_err:
            logger.error("Falló el envío a %s. Último error: %s", to_email, last_err)
        return False

    def send_bulk_html(
        self,
        to_emails: Iterable[str],
        subject: str,
        html: str,
        text: Optional[str] = None,
        *,
        cc: Union[str, Sequence[str], None] = None,
        bcc: Union[str, Sequence[str], None] = None,
        reply_to: Optional[str] = None,
        reuse_connection: bool = True,
    ) -> int:
        """
        Devuelve cantidad de envíos OK.
        reuse_connection=True => abre 1 conexión y manda muchos (más rápido / menos fallas).
        """
        emails = [e.strip() for e in to_emails if e and str(e).strip()]
        if not emails:
            return 0

        ok = 0
        try:
            for e in emails:
                if self.send_html(
                    e,
                    subject,
                    html,
                    text,
                    cc=cc,
                    bcc=bcc,
                    reply_to=reply_to,
                    reuse_connection=reuse_connection,
                ):
                    ok += 1
        finally:
            if reuse_connection:
                self.close()
        return ok
