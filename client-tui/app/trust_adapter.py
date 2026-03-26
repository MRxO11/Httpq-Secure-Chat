from dataclasses import dataclass
from typing import Any

try:
    from .httpq_client import HTTPQVerificationError, HTTPQVerifier, generate_client_nonce
except ImportError:
    from httpq_client import HTTPQVerificationError, HTTPQVerifier, generate_client_nonce


class TrustAdapterError(Exception):
    pass


@dataclass(frozen=True)
class TrustHelloPlan:
    client_nonce: str
    relay_id: str
    realm: str
    kt_log_url: str
    witness_url: str


@dataclass(frozen=True)
class TrustProofPlan:
    client_id: str
    verified: bool
    relay_id: str
    realm: str
    kt_log_url: str
    witness_url: str

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "client_id": self.client_id,
            "verified": self.verified,
            "relay_id": self.relay_id,
            "realm": self.realm,
            "kt_log_url": self.kt_log_url,
            "witness_url": self.witness_url,
        }

    @classmethod
    def from_contract_dict(cls, payload: dict[str, object | None]) -> "TrustProofPlan":
        return cls(
            client_id=str(payload.get("client_id", "")),
            verified=bool(payload.get("verified", False)),
            relay_id=str(payload.get("relay_id", "unknown")),
            realm=str(payload.get("realm", "unknown")),
            kt_log_url=str(payload.get("kt_log_url", "unknown")),
            witness_url=str(payload.get("witness_url", "unknown")),
        )


class TrustAdapter:
    def __init__(self, verifier: HTTPQVerifier) -> None:
        self.verifier = verifier
        self._last_hello: dict[str, Any] | None = None
        self._pending_client_nonce: str = ""

    @property
    def pending_client_nonce(self) -> str:
        return self._pending_client_nonce

    def handle_server_hello(self, payload: dict[str, Any]) -> TrustHelloPlan:
        self._last_hello = dict(payload)
        self._pending_client_nonce = generate_client_nonce()
        return TrustHelloPlan(
            client_nonce=self._pending_client_nonce,
            relay_id=str(payload.get("relayId", "unknown")),
            realm=str(payload.get("realm", "unknown")),
            kt_log_url=str(payload.get("ktLogUrl", "unknown")),
            witness_url=str(payload.get("witnessUrl", "unknown")),
        )

    def handle_server_proof(self, payload: dict[str, Any]) -> TrustProofPlan:
        if self._last_hello is None:
            raise TrustAdapterError("received relay proof before relay hello")

        if str(payload.get("clientNonce", "")) != self._pending_client_nonce:
            raise TrustAdapterError("HTTPq verification failed: client nonce mismatch")

        try:
            client_id = self.verifier.verify_server_proof(self._last_hello, payload)
        except HTTPQVerificationError as exc:
            raise TrustAdapterError(f"HTTPq verification failed: {exc}") from exc

        relay_id = str(self._last_hello.get("relayId", "unknown"))
        realm = str(self._last_hello.get("realm", "unknown"))
        kt_log_url = str(self._last_hello.get("ktLogUrl", "unknown"))
        witness_url = str(self._last_hello.get("witnessUrl", "unknown"))
        self._pending_client_nonce = ""
        return TrustProofPlan(
            client_id=client_id,
            verified=True,
            relay_id=relay_id,
            realm=realm,
            kt_log_url=kt_log_url,
            witness_url=witness_url,
        )
