from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# Password Engine — ULTRA FINAL / NO TOCAR
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_MAX_PASSWORD_LEN = 512  # defensa anti input malicioso


# ============================================================
# Policy / Config (ENV driven, sin Flask)
# ============================================================

@dataclass(frozen=True)
class PasswordPolicy:
    method: str = "pbkdf2:sha256"
    salt_len: int = 16
    min_len: int = 8
    use_pepper: bool = False
    pepper_env_key: str = "PASSWORD_PEPPER"


def get_policy() -> PasswordPolicy:
    method = (os.getenv("PASSWORD_METHOD") or "pbkdf2:sha256").strip()

    try:
        salt_len = int(os.getenv("PASSWORD_SALT_LEN") or "16")
    except Exception:
        salt_len = 16

    try:
        min_len = int(os.getenv("PASSWORD_MIN_LEN") or "8")
    except Exception:
        min_len = 8

    use_pepper = (os.getenv("PASSWORD_USE_PEPPER") or "").lower() in _TRUE

    # hard bounds anti config rota
    salt_len = min(max(salt_len, 8), 64)
    min_len = min(max(min_len, 6), 128)

    return PasswordPolicy(
        method=method,
        salt_len=salt_len,
        min_len=min_len,
        use_pepper=use_pepper,
        pepper_env_key="PASSWORD_PEPPER",
    )


# ============================================================
# Helpers internos (defensivos)
# ============================================================

def _clean(v: Optional[str]) -> str:
    return (v or "").strip()


def _pepper(policy: PasswordPolicy) -> str:
    if not policy.use_pepper:
        return ""
    return (os.getenv(policy.pepper_env_key) or "").strip()


def _apply_pepper(password: str, pepper: str) -> str:
    if not pepper:
        return password
    return f"{password}||{pepper}"


def _hash_looks_valid(password_hash: str) -> bool:
    h = _clean(password_hash)
    return bool(h and "$" in h and len(h) > 20)


def _needs_rehash(password_hash: str, policy: PasswordPolicy) -> bool:
    return policy.method not in password_hash


def validate_password(raw_password: str, policy: PasswordPolicy) -> Tuple[bool, str]:
    pwd = _clean(raw_password)
    if not pwd:
        return False, "La contraseña es obligatoria."
    if len(pwd) < policy.min_len:
        return False, f"La contraseña debe tener al menos {policy.min_len} caracteres."
    if len(pwd) > _MAX_PASSWORD_LEN:
        return False, "La contraseña es demasiado larga."
    return True, ""


# ============================================================
# API pública — ESTABLE
# ============================================================

def hash_password(raw_password: str) -> str:
    policy = get_policy()
    ok, msg = validate_password(raw_password, policy)
    if not ok:
        raise ValueError(msg)

    pwd = _apply_pepper(_clean(raw_password), _pepper(policy))

    return generate_password_hash(
        pwd,
        method=policy.method,
        salt_length=policy.salt_len,
    )


def verify_password(
    raw_password: str,
    password_hash: str,
    *,
    allow_rehash: bool = True,
) -> Tuple[bool, Optional[str]]:
    policy = get_policy()

    pwd = _clean(raw_password)
    hsh = _clean(password_hash)

    if not pwd or not hsh:
        return False, None

    if not _hash_looks_valid(hsh):
        return False, None

    pwd2 = _apply_pepper(pwd, _pepper(policy))

    try:
        ok = bool(check_password_hash(hsh, pwd2))
    except Exception:
        return False, None

    if not ok:
        # defensa timing extra
        hmac.compare_digest("x", "y")
        return False, None

    if allow_rehash and _needs_rehash(hsh, policy):
        try:
            return True, hash_password(pwd)
        except Exception:
            return True, None

    return True, None


def verify_and_maybe_rehash(
    raw_password: str,
    password_hash: str,
) -> Tuple[bool, Optional[str]]:
    return verify_password(raw_password, password_hash, allow_rehash=True)


__all__ = [
    "PasswordPolicy",
    "get_policy",
    "hash_password",
    "verify_password",
    "verify_and_maybe_rehash",
]
