"""Register the synthetic benchmark account on the local Vaultwarden.

Implemented from the documented Bitwarden key-derivation and EncString
protocol (PBKDF2-SHA256 master key, HKDF-Expand stretch, type-2 EncString:
AES-256-CBC + HMAC-SHA256). Only talks to 127.0.0.1.

Usage: scripts/bench/register.sh (wraps python3 -I with cryptography)
Env: BENCH_PASSWORD (default "correct horse battery staple"),
     BENCH_EMAIL (default alice@example.org), BENCH_URL (default
     http://127.0.0.1:8222; must be a loopback URL).
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 600_000


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 expand step only (no extract).
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def enc_string(plain: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def post(url: str, path: str, body: dict) -> tuple[int, str]:
    req = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def main() -> int:
    password = os.environ.get("BENCH_PASSWORD", "correct horse battery staple")
    email = os.environ.get("BENCH_EMAIL", "alice@example.org").strip().lower()
    url = os.environ.get("BENCH_URL", "http://127.0.0.1:8222").rstrip("/")
    host = urllib.parse.urlparse(url).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"refusing non-loopback server {url}", file=sys.stderr)
        return 2

    pw = password.encode("utf-8")
    master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode("utf-8"), ITERATIONS, 32)
    master_hash = b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
    stretched_enc = hkdf_expand(master_key, b"enc", 32)
    stretched_mac = hkdf_expand(master_key, b"mac", 32)

    user_key = os.urandom(64)
    protected_key = enc_string(user_key, stretched_enc, stretched_mac)

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_der = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    encrypted_private = enc_string(private_der, user_key[:32], user_key[32:])

    body = {
        "email": email,
        "name": email.split("@")[0],
        "masterPasswordHash": master_hash,
        "masterPasswordHint": None,
        "key": protected_key,
        "kdf": 0,
        "kdfIterations": ITERATIONS,
        "keys": {"publicKey": b64(public_der), "encryptedPrivateKey": encrypted_private},
    }
    status, text = post(url, "/identity/accounts/register", body)
    if status == 404:
        # Vaultwarden >= 1.34 (web 2025.x) dropped the one-shot route for the
        # two-step flow. With no SMTP configured, send-verification-email
        # answers with the verification token itself instead of mailing it.
        status, text = post(
            url,
            "/identity/accounts/register/send-verification-email",
            {"email": email, "name": body["name"], "receiveMarketingEmails": False},
        )
        if status != 200 or not text.strip():
            print(f"send-verification-email failed: HTTP {status}: {text[:300]}", file=sys.stderr)
            return 1
        token = text.strip().strip('"')
        finish = {
            "email": email,
            "emailVerificationToken": token,
            "masterPasswordHash": master_hash,
            "masterPasswordHint": None,
            "userSymmetricKey": protected_key,
            "userAsymmetricKeys": body["keys"],
            "kdf": 0,
            "kdfIterations": ITERATIONS,
        }
        status, text = post(url, "/identity/accounts/register/finish", finish)
    if status == 200:
        print(f"registered {email} on {url}")
        return 0
    if "already exists" in text or "already registered" in text:
        print(f"{email} already registered on {url}")
        return 0
    print(f"registration failed: HTTP {status}: {text[:300]}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
