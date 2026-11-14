"""Cryptographic primitives for VaultPOS: PBKDF2-HMAC-SHA256 + NIST SP 800-38D AES-256-GCM."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _NativeAESGCM
except ImportError:  # pragma: no cover - standard library pure-Python fallback
    _NativeAESGCM = None

DEFAULT_PBKDF2_ITERATIONS = 50_000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
BACKUP_SCHEMA_V2 = "ENC_BACKUP_V2"

_GF128_R = 0xE1000000000000000000000000000000

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


class VaultCryptoError(ValueError):
    """Raised when key parameters, envelope structure, or GCM authentication fail."""


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if (value & 0x80) else (value << 1) & 0xFF


def _expand_key_256(key: bytes) -> list[bytes]:
    """Expand a 32-byte AES-256 key into 15 round keys of 16 bytes each."""
    if len(key) != KEY_BYTES:
        raise VaultCryptoError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")
    words = [list(key[i : i + 4]) for i in range(0, KEY_BYTES, 4)]
    for i in range(8, 60):
        temp = list(words[i - 1])
        if i % 8 == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // 8 - 1], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - 8][j] ^ temp[j] for j in range(4)])
    return [bytes(b for word in words[r * 4 : (r + 1) * 4] for b in word) for r in range(15)]


def _aes256_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Encrypt a single 16-byte block with pre-expanded AES-256 round keys."""
    state = bytearray(a ^ b for a, b in zip(block, round_keys[0]))
    for r in range(1, 15):
        for idx in range(16):
            state[idx] = _SBOX[state[idx]]
        # ShiftRows on column-major 4x4 state
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        if r < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c], state[c + 1], state[c + 2], state[c + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                state[c] ^= t ^ _xtime(a0 ^ a1)
                state[c + 1] ^= t ^ _xtime(a1 ^ a2)
                state[c + 2] ^= t ^ _xtime(a2 ^ a3)
                state[c + 3] ^= t ^ _xtime(a3 ^ a0)
        rk = round_keys[r]
        for idx in range(16):
            state[idx] ^= rk[idx]
    return bytes(state)


def _gf128_mul(x: int, y: int) -> int:
    """Multiply two 128-bit polynomials in GF(2^128) per NIST SP 800-38D Algorithm 1."""
    z = 0
    v = y
    for bit_idx in range(127, -1, -1):
        if (x >> bit_idx) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= _GF128_R
    return z


def _ghash_blocks(h_int: int, acc: int, data: bytes) -> int:
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        if len(chunk) < 16:
            chunk = chunk.ljust(16, b"\x00")
        acc = _gf128_mul(acc ^ int.from_bytes(chunk, "big"), h_int)
    return acc


def _ghash(h_int: int, aad: bytes, ciphertext: bytes) -> bytes:
    acc = _ghash_blocks(h_int, 0, aad)
    acc = _ghash_blocks(h_int, acc, ciphertext)
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    acc = _gf128_mul(acc ^ lengths, h_int)
    return acc.to_bytes(16, "big")


def _inc32(counter_block: bytes) -> bytes:
    counter_val = (int.from_bytes(counter_block[12:], "big") + 1) & 0xFFFFFFFF
    return counter_block[:12] + counter_val.to_bytes(4, "big")


def _gctr(round_keys: list[bytes], icb: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray()
    cb = icb
    for offset in range(0, len(data), 16):
        keystream = _aes256_encrypt_block(cb, round_keys)
        chunk = data[offset : offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        cb = _inc32(cb)
    return bytes(out)


def _derive_j0(h_int: int, nonce: bytes) -> bytes:
    if len(nonce) == NONCE_BYTES:
        return nonce + b"\x00\x00\x00\x01"
    return _ghash(h_int, b"", nonce)


def _pure_aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    if not nonce:
        raise VaultCryptoError("AES-GCM nonce cannot be empty")
    round_keys = _expand_key_256(key)
    h_int = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, round_keys), "big")
    j0 = _derive_j0(h_int, nonce)
    ciphertext = _gctr(round_keys, _inc32(j0), plaintext)
    tag_mask = _aes256_encrypt_block(j0, round_keys)
    ghash_digest = _ghash(h_int, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(ghash_digest, tag_mask))
    return ciphertext, tag


def _pure_aes256_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes:
    if not nonce:
        raise VaultCryptoError("AES-GCM nonce cannot be empty")
    if len(tag) != TAG_BYTES:
        raise VaultCryptoError(f"Expected 16-byte GCM authentication tag, got {len(tag)}")
    round_keys = _expand_key_256(key)
    h_int = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, round_keys), "big")
    j0 = _derive_j0(h_int, nonce)
    tag_mask = _aes256_encrypt_block(j0, round_keys)
    expected_tag = bytes(a ^ b for a, b in zip(_ghash(h_int, aad, ciphertext), tag_mask))
    if not hmac.compare_digest(expected_tag, tag):
        raise VaultCryptoError("AES-256-GCM authentication tag mismatch (invalid password or corrupted vault)")
    return _gctr(round_keys, _inc32(j0), ciphertext)


def aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt plaintext under AES-256-GCM and return `(ciphertext, 16-byte tag)`."""
    if len(key) != KEY_BYTES:
        raise VaultCryptoError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")
    if _NativeAESGCM is not None:  # pragma: no cover - accelerated path when optional dependency is present
        combined = _NativeAESGCM(key).encrypt(nonce, plaintext, aad)
        return combined[:-TAG_BYTES], combined[-TAG_BYTES:]
    return _pure_aes256_gcm_encrypt(key, nonce, plaintext, aad)


def aes256_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Authenticate and decrypt AES-256-GCM `(ciphertext, tag)`, raising `VaultCryptoError` on tamper."""
    if len(key) != KEY_BYTES:
        raise VaultCryptoError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")
    if len(tag) != TAG_BYTES:
        raise VaultCryptoError(f"Expected 16-byte GCM authentication tag, got {len(tag)}")
    if _NativeAESGCM is not None:  # pragma: no cover - accelerated path when optional dependency is present
        try:
            return _NativeAESGCM(key).decrypt(nonce, ciphertext + tag, aad)
        except Exception as exc:
            raise VaultCryptoError("AES-256-GCM authentication tag mismatch") from exc
    return _pure_aes256_gcm_decrypt(key, nonce, ciphertext, tag, aad)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256."""
    if not password:
        raise VaultCryptoError("Password cannot be empty")
    if len(salt) < SALT_BYTES:
        raise VaultCryptoError(f"Salt must be at least {SALT_BYTES} bytes")
    if iterations < 10_000:
        raise VaultCryptoError("PBKDF2 iteration count is below minimum security threshold (10,000)")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=KEY_BYTES)


def hash_password(
    password: str,
    salt: bytes | None = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> dict[str, Any]:
    """Produce a salted PBKDF2-HMAC-SHA256 password verification record."""
    actual_salt = salt if salt is not None else os.urandom(SALT_BYTES)
    digest = derive_key(password, actual_salt, iterations=iterations)
    return {
        "kdf": "PBKDF2-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(actual_salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def verify_password(password: str, record: dict[str, Any]) -> bool:
    """Constant-time verification against a salted PBKDF2-SHA256 record."""
    try:
        if record.get("kdf") != "PBKDF2-SHA256":
            return False
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["hash"], validate=True)
        iterations = int(record["iterations"])
        candidate = derive_key(password, salt, iterations=iterations)
        return hmac.compare_digest(candidate, expected)
    except (KeyError, TypeError, ValueError, VaultCryptoError):
        return False


def encrypt_json_envelope(
    payload: Any,
    password: str,
    *,
    aad: bytes = b"",
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> dict[str, Any]:
    """Serialize JSON and protect it in an `ENC_BACKUP_V2` PBKDF2 + AES-256-GCM envelope."""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = derive_key(password, salt, iterations=iterations)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext, tag = aes256_gcm_encrypt(key, nonce, plaintext, aad=aad)
    return {
        "schema": BACKUP_SCHEMA_V2,
        "kdf": "PBKDF2-SHA256",
        "cipher": "AES-256-GCM",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_json_envelope(
    envelope: dict[str, Any],
    password: str,
    *,
    aad: bytes = b"",
) -> Any:
    """Verify and decrypt an `ENC_BACKUP_V2` JSON envelope."""
    if not isinstance(envelope, dict):
        raise VaultCryptoError("Encrypted envelope must be a JSON object")
    if envelope.get("schema") != BACKUP_SCHEMA_V2:
        raise VaultCryptoError(f"Unsupported vault schema: {envelope.get('schema')!r}")
    if envelope.get("kdf") != "PBKDF2-SHA256" or envelope.get("cipher") != "AES-256-GCM":
        raise VaultCryptoError("Unsupported cryptographic suite in vault envelope")
    try:
        iterations = int(envelope["iterations"])
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultCryptoError("Malformed encrypted vault envelope fields") from exc
    if len(nonce) != NONCE_BYTES:
        raise VaultCryptoError(f"Invalid AES-GCM nonce length: {len(nonce)}")
    key = derive_key(password, salt, iterations=iterations)
    plaintext = aes256_gcm_decrypt(key, nonce, ciphertext, tag, aad=aad)
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultCryptoError("Decrypted vault payload is not valid UTF-8 JSON") from exc
