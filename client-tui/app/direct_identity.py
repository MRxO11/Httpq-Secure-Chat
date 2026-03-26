import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

try:
    from .local_state_crypto import load_json as load_state_json, save_json as save_state_json
except ImportError:
    from local_state_crypto import load_json as load_state_json, save_json as save_state_json


@dataclass
class DirectIdentity:
    encryption_private_key: X25519PrivateKey
    encryption_public_key: X25519PublicKey
    signing_private_key: Ed25519PrivateKey
    signing_public_key: Ed25519PublicKey

    @property
    def encryption_public_key_b64(self) -> str:
        return base64.b64encode(
            self.encryption_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")

    @property
    def signing_public_key_b64(self) -> str:
        return base64.b64encode(
            self.signing_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")


class DirectIdentityStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv(
            "DIRECT_IDENTITY_FILE",
            os.path.join(os.path.expanduser("~"), ".secure-chat", "direct-identity.json"),
        )

    def load_or_create(self) -> DirectIdentity:
        if os.path.exists(self.path):
            data = load_state_json(self.path)
            encryption_private_key = X25519PrivateKey.from_private_bytes(
                base64.b64decode(data["encryptionPrivateKey"])
            )
            signing_private_key = Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(data["signingPrivateKey"])
            )
            return DirectIdentity(
                encryption_private_key=encryption_private_key,
                encryption_public_key=encryption_private_key.public_key(),
                signing_private_key=signing_private_key,
                signing_public_key=signing_private_key.public_key(),
            )

        encryption_private_key = X25519PrivateKey.generate()
        signing_private_key = Ed25519PrivateKey.generate()
        save_state_json(
            self.path,
            {
                "encryptionPrivateKey": base64.b64encode(
                    encryption_private_key.private_bytes(
                        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                    )
                ).decode("ascii"),
                "signingPrivateKey": base64.b64encode(
                    signing_private_key.private_bytes(
                        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                    )
                ).decode("ascii"),
            },
        )
        return DirectIdentity(
            encryption_private_key=encryption_private_key,
            encryption_public_key=encryption_private_key.public_key(),
            signing_private_key=signing_private_key,
            signing_public_key=signing_private_key.public_key(),
        )
