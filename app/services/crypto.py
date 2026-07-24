import os
import hashlib
import hmac
import secrets
import string
from datetime import datetime, timezone, timedelta

import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


from app.config import settings

ENCRYPTION_KEY = settings.ENCRYPTION_KEY


def encrypt_aes(plain_text: str) -> str:
    if not plain_text:
        return ""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plain_text.encode()) + padder.finalize()
    ct = encryptor.update(padded) + encryptor.finalize()
    return __import__("base64").b64encode(iv + ct).decode()


def decrypt_aes(cipher_text: str) -> str:
    if not cipher_text:
        return ""
    import base64
    data = base64.b64decode(cipher_text)
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def generate_license_key(prefix: str = "KA") -> str:
    segments = [prefix]
    for _ in range(4):
        seg = secrets.token_hex(4).upper()
        segments.append(seg)
    return "-".join(segments)


def generate_secret_id() -> str:
    return secrets.token_hex(16)


def generate_secret_key() -> str:
    return secrets.token_hex(32).upper()


def generate_owner_secret() -> str:
    return secrets.token_hex(24).upper()


def generate_session_token() -> str:
    token = secrets.token_urlsafe(48)
    return token


def compute_hmac(message: str, secret: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_hmac(message: str, secret: str, signature: str) -> bool:
    computed = compute_hmac(message, secret)
    return hmac.compare_digest(computed, signature)


def get_machine_hash(identifier: str) -> str:
    return hashlib.sha256(identifier.encode()).hexdigest().upper()
