import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class LocalStateCryptoError(Exception):
    pass


def state_passphrase() -> str | None:
    value = os.getenv("LOCAL_STATE_PASSPHRASE", "").strip()
    return value or None


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    decoded = json.loads(raw)
    if not _looks_encrypted(decoded):
        return decoded
    passphrase = state_passphrase()
    if passphrase is None:
        raise LocalStateCryptoError(
            "encrypted local state requires LOCAL_STATE_PASSPHRASE to be set"
        )
    return _decrypt_payload(decoded, passphrase)


def save_json(path: str, payload) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    passphrase = state_passphrase()
    encoded_payload = payload
    if passphrase is not None:
        encoded_payload = _encrypt_payload(payload, passphrase)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(encoded_payload, handle, indent=2, sort_keys=True)


def _looks_encrypted(payload) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("v") == 1
        and payload.get("cipher") == "aes-256-gcm"
        and payload.get("kdf") == "scrypt"
        and "salt" in payload
        and "nonce" in payload
        and "ciphertext" in payload
    )


def _encrypt_payload(payload, passphrase: str) -> dict[str, str | int]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "v": 1,
        "cipher": "aes-256-gcm",
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_payload(payload: dict[str, str | int], passphrase: str):
    try:
        salt = base64.b64decode(str(payload["salt"]))
        nonce = base64.b64decode(str(payload["nonce"]))
        ciphertext = base64.b64decode(str(payload["ciphertext"]))
        key = _derive_key(passphrase, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise LocalStateCryptoError("failed to decrypt local state") from exc


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))
