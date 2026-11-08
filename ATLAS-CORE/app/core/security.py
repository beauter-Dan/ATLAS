"""Cryptographic primitives: password hashing, opaque tokens, TOTP (RFC 6238), secret vault."""
import base64, hashlib, hmac, os, secrets, struct, time
from cryptography.fernet import Fernet
from app.core.config import get_settings

PBKDF2 = "pbkdf2_sha256"
LEGACY_ITERATIONS = 200_000  # milestone-1 format: "salt$hash"


def hash_password(pw: str, iterations: int | None = None, salt: bytes | None = None) -> str:
    it = iterations or get_settings().password_hash_iterations
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)
    return f"{PBKDF2}${it}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def _parse(stored: str) -> tuple[int, bytes, bytes]:
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == PBKDF2:
        return int(parts[1]), base64.b64decode(parts[2]), base64.b64decode(parts[3])
    if len(parts) == 2:
        return LEGACY_ITERATIONS, base64.b64decode(parts[0]), base64.b64decode(parts[1])
    raise ValueError("unrecognized hash format")


def verify_password(pw: str, stored: str) -> bool:
    try:
        it, salt, dk = _parse(stored)
    except Exception:
        return False
    return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it), dk)


def needs_rehash(stored: str) -> bool:
    try:
        it, _, _ = _parse(stored)
        return it < get_settings().password_hash_iterations or not stored.startswith(PBKDF2 + "$")
    except Exception:
        return True


_dummy: str | None = None


def dummy_hash() -> str:
    """Verified against for unknown usernames so timing does not reveal account existence."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password("not-a-real-password")
    return _dummy


# ---- opaque tokens (only hashes are stored server-side)
def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---- secret vault (credentials, MFA seeds)
def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"vault:" + get_settings().secret_key.encode()).digest()))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# ---- TOTP
def totp_new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp_step(t: float | None = None) -> int:
    return int((t if t is not None else time.time()) // 30)


def totp_code(secret: str, t: float | None = None) -> str:
    return _hotp(secret, totp_step(t))


def totp_verify(secret: str, code: str, last_step: int | None = None, t: float | None = None, window: int = 1) -> int | None:
    """Returns the matched time-step (store it to block replay) or None."""
    if not (code or "").isdigit() or len(code) != 6:
        return None
    now = totp_step(t)
    for d in range(-window, window + 1):
        step = now + d
        if hmac.compare_digest(_hotp(secret, step), code) and (last_step is None or step > last_step):
            return step
    return None


def totp_uri(secret: str, username: str) -> str:
    from urllib.parse import quote
    issuer = get_settings().mfa_issuer
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}"
