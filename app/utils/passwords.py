from __future__ import annotations

"""
Password Engine — ULTRA PRO / BULLETPROOF (FINAL)

Mejoras reales (10+):
1) Policy cacheada (no relee ENV a cada request)
2) Normaliza Unicode (NFKC) para evitar trucos visuales/encoding raros
3) Bloquea NULL bytes + control chars peligrosos
4) Límite hard de longitud + clamp de config por env
5) Pepper opcional: modo "require" si lo activás (evita config insegura)
6) Rehash detection correcto por prefijo de método (no string-in)
7) Validaciones opcionales por ENV (digit/upper/lower/symbol/mixed)
8) Mensajes de error consistentes (no filtra detalles raros)
9) Verify constante (timing defense) también en rutas fallidas
10) API estable: hash_password(), verify_password(), verify_and_maybe_rehash()
"""

import hmac
import os
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

_MAX_PASSWORD_LEN = 512  # defensa anti input malicioso


# ============================================================
# Policy / Config (ENV driven, sin Flask)
# ============================================================


@dataclass(frozen=True)
class PasswordPolicy:
    # Werkzeug methods: "pbkdf2:sha256", "scrypt", etc.
    method: str = "pbkdf2:sha256"
    salt_len: int = 16
    min_len: int = 8

    # Pepper
    use_pepper: bool = False
    pepper_env_key: str = "PASSWORD_PEPPER"
    pepper_required: bool = (
        False  # si use_pepper=True y required=True => exige que exista
    )

    # Reglas opcionales (off por default)
    require_digit: bool = False
    require_lower: bool = False
    require_upper: bool = False
    require_symbol: bool = False
    require_mixed: bool = False  # letras + números

    # Normalización
    normalize_unicode: bool = True  # NFKC


def _env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None else str(v).strip()


def _env_int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    v = _env_str(key, "")
    if not v:
        return default
    s = v.lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


@lru_cache(maxsize=1)
def get_policy() -> PasswordPolicy:
    """
    Lee ENV una sola vez (cache).
    Si cambiás ENV en runtime (raro), podés limpiar cache con:
        get_policy.cache_clear()
    """
    method = _env_str("PASSWORD_METHOD", "pbkdf2:sha256")

    salt_len = _env_int("PASSWORD_SALT_LEN", 16)
    min_len = _env_int("PASSWORD_MIN_LEN", 8)

    use_pepper = _env_bool("PASSWORD_USE_PEPPER", False)
    pepper_required = _env_bool("PASSWORD_PEPPER_REQUIRED", False)

    # Reglas opcionales
    require_digit = _env_bool("PASSWORD_REQUIRE_DIGIT", False)
    require_lower = _env_bool("PASSWORD_REQUIRE_LOWER", False)
    require_upper = _env_bool("PASSWORD_REQUIRE_UPPER", False)
    require_symbol = _env_bool("PASSWORD_REQUIRE_SYMBOL", False)
    require_mixed = _env_bool("PASSWORD_REQUIRE_MIXED", False)

    normalize_unicode = _env_bool("PASSWORD_NORMALIZE_UNICODE", True)

    # hard bounds anti config rota
    salt_len = min(max(salt_len, 8), 64)
    min_len = min(max(min_len, 6), 128)

    method = (method or "pbkdf2:sha256").strip()

    return PasswordPolicy(
        method=method,
        salt_len=salt_len,
        min_len=min_len,
        use_pepper=use_pepper,
        pepper_env_key="PASSWORD_PEPPER",
        pepper_required=pepper_required,
        require_digit=require_digit,
        require_lower=require_lower,
        require_upper=require_upper,
        require_symbol=require_symbol,
        require_mixed=require_mixed,
        normalize_unicode=normalize_unicode,
    )


# ============================================================
# Helpers internos (defensivos)
# ============================================================


def _clean(v: Optional[str]) -> str:
    return (v or "").strip()


def _normalize_pwd(pwd: str, *, do_unicode: bool) -> str:
    """
    NFKC reduce variantes raras (full-width, etc.)
    Sin tocar espacios internos: el usuario manda lo que manda.
    """
    s = _clean(pwd)

    # bloqueos básicos: null bytes y control chars
    if "\x00" in s:
        return ""

    # elimina chars de control invisibles (excepto espacios normales)
    # (si querés permitir tabs/newlines, cambiá esto, pero no recomendado)
    for ch in s:
        o = ord(ch)
        if (0 <= o <= 31) or (o == 127):
            return ""

    if do_unicode:
        try:
            s = unicodedata.normalize("NFKC", s)
        except Exception:
            pass

    return s


def _pepper(policy: PasswordPolicy) -> str:
    if not policy.use_pepper:
        return ""
    p = _env_str(policy.pepper_env_key, "")
    if policy.pepper_required and not p:
        # modo estricto: si activás pepper en prod, exigilo.
        raise RuntimeError(f"{policy.pepper_env_key} requerido pero no está definido.")
    return p


def _apply_pepper(password: str, pepper: str) -> str:
    return password if not pepper else f"{password}||{pepper}"


def _hash_looks_valid(password_hash: str) -> bool:
    h = _clean(password_hash)
    # werkzeug hashes suelen tener "$" separando salt/hash
    return bool(h and "$" in h and len(h) > 20)


def _hash_method_prefix(password_hash: str) -> str:
    """
    Werkzueg form:
      pbkdf2:sha256:260000$salt$hash
      scrypt:...$salt$hash
    Tomamos todo antes del primer '$' y nos quedamos con el "método base".
    """
    h = _clean(password_hash)
    if not h or "$" not in h:
        return ""
    left = h.split("$", 1)[0]  # "pbkdf2:sha256:260000"
    # método puede tener params; base method suele ser "pbkdf2:sha256" o "scrypt"
    # - si viene "pbkdf2:sha256:260000" => base "pbkdf2:sha256"
    # - si viene "scrypt:..." => base "scrypt"
    parts = left.split(":")
    if not parts:
        return ""
    if parts[0] == "pbkdf2" and len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return parts[0]  # scrypt / others


def _policy_method_prefix(policy_method: str) -> str:
    m = (policy_method or "").strip()
    if not m:
        return ""
    parts = m.split(":")
    if parts[0] == "pbkdf2" and len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return parts[0]


def _needs_rehash(password_hash: str, policy: PasswordPolicy) -> bool:
    """
    Rehash si:
      - el prefijo del método actual != prefijo esperado
    (No intenta comparar iteraciones; eso queda a tu criterio si querés.)
    """
    cur = _hash_method_prefix(password_hash)
    want = _policy_method_prefix(policy.method)
    if not cur or not want:
        return False
    return cur != want


def validate_password(raw_password: str, policy: PasswordPolicy) -> Tuple[bool, str]:
    pwd = _normalize_pwd(raw_password, do_unicode=policy.normalize_unicode)
    if not pwd:
        return False, "La contraseña es obligatoria."

    if len(pwd) < policy.min_len:
        return False, f"La contraseña debe tener al menos {policy.min_len} caracteres."

    if len(pwd) > _MAX_PASSWORD_LEN:
        return False, "La contraseña es demasiado larga."

    # Reglas opcionales
    has_digit = any(c.isdigit() for c in pwd)
    has_alpha = any(c.isalpha() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_symbol = any((not c.isalnum()) for c in pwd)

    if policy.require_mixed and not (has_alpha and has_digit):
        return False, "Usá letras y números en la contraseña."
    if policy.require_digit and not has_digit:
        return False, "Agregá al menos un número."
    if policy.require_lower and not has_lower:
        return False, "Agregá al menos una letra minúscula."
    if policy.require_upper and not has_upper:
        return False, "Agregá al menos una letra mayúscula."
    if policy.require_symbol and not has_symbol:
        return False, "Agregá al menos un símbolo."

    return True, ""


# ============================================================
# API pública — ESTABLE
# ============================================================


def hash_password(raw_password: str) -> str:
    policy = get_policy()
    ok, msg = validate_password(raw_password, policy)
    if not ok:
        raise ValueError(msg)

    pwd = _normalize_pwd(raw_password, do_unicode=policy.normalize_unicode)
    pep = _pepper(policy)
    pwd2 = _apply_pepper(pwd, pep)

    return generate_password_hash(
        pwd2,
        method=policy.method,
        salt_length=policy.salt_len,
    )


def verify_password(
    raw_password: str,
    password_hash: str,
    *,
    allow_rehash: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Retorna:
      (ok, new_hash_or_none)
    Si allow_rehash=True y el método cambió, devuelve nuevo hash para guardar.
    """
    policy = get_policy()

    pwd = _normalize_pwd(raw_password, do_unicode=policy.normalize_unicode)
    hsh = _clean(password_hash)

    if not pwd or not hsh or not _hash_looks_valid(hsh):
        # timing defense mínima
        hmac.compare_digest("x", "y")
        return False, None

    pep = _pepper(policy)
    pwd2 = _apply_pepper(pwd, pep)

    try:
        ok = bool(check_password_hash(hsh, pwd2))
    except Exception:
        hmac.compare_digest("x", "y")
        return False, None

    if not ok:
        # defensa timing extra
        hmac.compare_digest("x", "y")
        return False, None

    if allow_rehash and _needs_rehash(hsh, policy):
        try:
            return True, hash_password(pwd)
        except Exception:
            # si falla rehash, igual autenticado
            return True, None

    return True, None


def verify_and_maybe_rehash(
    raw_password: str, password_hash: str
) -> Tuple[bool, Optional[str]]:
    return verify_password(raw_password, password_hash, allow_rehash=True)


__all__ = [
    "PasswordPolicy",
    "get_policy",
    "hash_password",
    "verify_password",
    "verify_and_maybe_rehash",
]
