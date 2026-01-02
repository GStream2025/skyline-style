# app/utils/password_engine.py
"""
Skyline Store — Password Engine (ULTRA PRO / FINAL)
---------------------------------------------------
Objetivo: hashing/verificación de passwords profesional y estable.

✅ Seguro por defecto (PBKDF2-SHA256)
✅ Configurable por ENV (sin Flask)
✅ Pepper opcional (ENV) + compare en tiempo constante
✅ Defensa anti input malicioso (largo máximo)
✅ verify() retorna bool
✅ verify_and_maybe_rehash() retorna (ok, new_hash|None)
✅ Auto-rehash cuando cambia policy
✅ Códigos claros y sin “magia”
✅ Sin dependencias extra (solo werkzeug)

ENV soportadas:
- PASSWORD_METHOD="pbkdf2:sha256"         (werkzeug)
- PASSWORD_SALT_LEN="16"
- PASSWORD_MIN_LEN="8"
- PASSWORD_MAX_LEN="512"
- PASSWORD_USE_PEPPER="0|1"
- PASSWORD_PEPPER="tu_secreto_largo"
- PASSWORD_ALLOW_WEAK="0|1"              (si 1, NO exige letras/números)
- PASSWORD_REQUIRE_MIX="1|0"             (si 1, exige letras + números)
- PASSWORD_REQUIRE_UPPER="0|1"           (si 1, exige mayúscula)
- PASSWORD_REQUIRE_SYMBOL="0|1"          (si 1, exige símbolo)
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# Constantes / Helpers ENV
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

_DEFAULT_METHOD = "pbkdf2:sha256"
_DEFAULT_SALT_LEN = 16
_DEFAULT_MIN_LEN = 8
_DEFAULT_MAX_LEN = 512  # defensa anti abuso


def _env(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()


def _env_int(key: str, default: int) -> int:
    v = _env(key, "")
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    v = _env(key, "")
    if not v:
        return default
    s = v.lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _clean(v: Optional[str]) -> str:
    return (v or "").strip()


# ============================================================
# Policy
# ============================================================

@dataclass(frozen=True)
class PasswordPolicy:
    method: str = _DEFAULT_METHOD
    salt_len: int = _DEFAULT_SALT_LEN
    min_len: int = _DEFAULT_MIN_LEN
    max_len: int = _DEFAULT_MAX_LEN

    use_pepper: bool = False
    pepper_env_key: str = "PASSWORD_PEPPER"

    # Reglas (opcionales)
    allow_weak: bool = False
    require_mix: bool = True
    require_upper: bool = False
    require_symbol: bool = False


def get_policy() -> PasswordPolicy:
    method = _env("PASSWORD_METHOD", _DEFAULT_METHOD)

    salt_len = _env_int("PASSWORD_SALT_LEN", _DEFAULT_SALT_LEN)
    min_len = _env_int("PASSWORD_MIN_LEN", _DEFAULT_MIN_LEN)
    max_len = _env_int("PASSWORD_MAX_LEN", _DEFAULT_MAX_LEN)

    # hard bounds (evita config rota)
    salt_len = min(max(salt_len, 8), 64)
    min_len = min(max(min_len, 6), 128)
    max_len = min(max(max_len, 128), 4096)

    use_pepper = _env_bool("PASSWORD_USE_PEPPER", default=False)

    allow_weak = _env_bool("PASSWORD_ALLOW_WEAK", default=False)
    require_mix = _env_bool("PASSWORD_REQUIRE_MIX", default=True)
    require_upper = _env_bool("PASSWORD_REQUIRE_UPPER", default=False)
    require_symbol = _env_bool("PASSWORD_REQUIRE_SYMBOL", default=False)

    # si allow_weak = 1, apagamos requisitos extra
    if allow_weak:
        require_mix = False
        require_upper = False
        require_symbol = False

    return PasswordPolicy(
        method=method,
        salt_len=salt_len,
        min_len=min_len,
        max_len=max_len,
        use_pepper=use_pepper,
        pepper_env_key="PASSWORD_PEPPER",
        allow_weak=allow_weak,
        require_mix=require_mix,
        require_upper=require_upper,
        require_symbol=require_symbol,
    )


# ============================================================
# Pepper
# ============================================================

def _pepper(policy: PasswordPolicy) -> str:
    if not policy.use_pepper:
        return ""
    return _env(policy.pepper_env_key, "")


def _apply_pepper(password: str, pepper: str) -> str:
    if not pepper:
        return password
    # separador estable
    return f"{password}||{pepper}"


# ============================================================
# Validación (robusta)
# ============================================================

_RE_HAS_LETTER = re.compile(r"[A-Za-z]")
_RE_HAS_DIGIT = re.compile(r"\d")
_RE_HAS_UPPER = re.compile(r"[A-Z]")
_RE_HAS_SYMBOL = re.compile(r"[^A-Za-z0-9]")


def validate_password(raw_password: str, policy: Optional[PasswordPolicy] = None) -> Tuple[bool, str]:
    pol = policy or get_policy()
    pwd = _clean(raw_password)

    if not pwd:
        return False, "La contraseña es obligatoria."

    if len(pwd) < pol.min_len:
        return False, f"La contraseña debe tener al menos {pol.min_len} caracteres."

    if len(pwd) > pol.max_len:
        return False, "La contraseña es demasiado larga."

    # reglas opcionales (activas por default: mix letras+números)
    if pol.require_mix:
        if not (_RE_HAS_LETTER.search(pwd) and _RE_HAS_DIGIT.search(pwd)):
            return False, "La contraseña debe incluir letras y números."

    if pol.require_upper:
        if not _RE_HAS_UPPER.search(pwd):
            return False, "La contraseña debe incluir al menos 1 mayúscula."

    if pol.require_symbol:
        if not _RE_HAS_SYMBOL.search(pwd):
            return False, "La contraseña debe incluir al menos 1 símbolo."

    return True, ""


# ============================================================
# Hashing / Verify
# ============================================================

def _hash_looks_valid(password_hash: str) -> bool:
    """
    Heurística rápida para evitar check_password_hash() con basura.
    """
    h = _clean(password_hash)
    return bool(h and "$" in h and len(h) > 20)


def _needs_rehash(password_hash: str, policy: PasswordPolicy) -> bool:
    """
    Si cambiaste el método en ENV, re-hash al próximo login.
    """
    h = _clean(password_hash)
    method = (policy.method or "").strip()
    return bool(method and method not in h)


def hash_password(raw_password: str) -> str:
    pol = get_policy()
    ok, msg = validate_password(raw_password, pol)
    if not ok:
        raise ValueError(msg)

    pwd = _apply_pepper(_clean(raw_password), _pepper(pol))

    return generate_password_hash(
        pwd,
        method=pol.method,
        salt_length=pol.salt_len,
    )


def verify_password(raw_password: str, password_hash: str) -> bool:
    """
    ✅ Devuelve bool (simple).
    """
    pol = get_policy()

    pwd = _clean(raw_password)
    hsh = _clean(password_hash)

    if not pwd or not hsh:
        return False

    if not _hash_looks_valid(hsh):
        return False

    pwd2 = _apply_pepper(pwd, _pepper(pol))

    try:
        ok = bool(check_password_hash(hsh, pwd2))
    except Exception:
        return False

    if not ok:
        # defensa timing (extra, barato)
        hmac.compare_digest("x", "y")
        return False

    return True


def verify_and_maybe_rehash(raw_password: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    """
    ✅ Verifica y si el hash quedó viejo (cambió PASSWORD_METHOD),
       retorna (True, new_hash).
    ✅ Si no necesita rehash, retorna (True, None).
    ✅ Si falla, retorna (False, None).
    """
    pol = get_policy()

    pwd = _clean(raw_password)
    hsh = _clean(password_hash)

    if not pwd or not hsh:
        return False, None

    if not _hash_looks_valid(hsh):
        return False, None

    pwd2 = _apply_pepper(pwd, _pepper(pol))

    try:
        ok = bool(check_password_hash(hsh, pwd2))
    except Exception:
        return False, None

    if not ok:
        hmac.compare_digest("x", "y")
        return False, None

    if _needs_rehash(hsh, pol):
        try:
            return True, hash_password(pwd)
        except Exception:
            # si algo raro pasa (config rota), no bloqueamos login
            return True, None

    return True, None


__all__ = [
    "PasswordPolicy",
    "get_policy",
    "validate_password",
    "hash_password",
    "verify_password",
    "verify_and_maybe_rehash",
]
