from dataclasses import dataclass
from typing import Any


class HTTPQProtocolError(Exception):
    pass


@dataclass(frozen=True)
class HTTPQClientHello:
    client_id: str
    client_nonce_b64: str

    def validate(self) -> None:
        if not self.client_id.strip():
            raise HTTPQProtocolError("HTTPq client hello is missing client id")
        if not self.client_nonce_b64.strip():
            raise HTTPQProtocolError("HTTPq client hello is missing client nonce")


@dataclass(frozen=True)
class HTTPQServerHello:
    relay_id: str
    realm: str
    protocol_version: str
    kt_log_url: str
    witness_url: str
    server_nonce_b64: str
    relay_public_key_b64: str

    def validate(self) -> None:
        if not self.relay_id.strip():
            raise HTTPQProtocolError("HTTPq server hello is missing relay id")
        if not self.realm.strip():
            raise HTTPQProtocolError("HTTPq server hello is missing realm")
        if not self.protocol_version.strip():
            raise HTTPQProtocolError("HTTPq server hello is missing protocol version")
        if not self.server_nonce_b64.strip():
            raise HTTPQProtocolError("HTTPq server hello is missing server nonce")
        if not self.relay_public_key_b64.strip():
            raise HTTPQProtocolError("HTTPq server hello is missing relay public key")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "HTTPQServerHello":
        hello = cls(
            relay_id=str(payload.get("relayId", "")),
            realm=str(payload.get("realm", "")),
            protocol_version=str(payload.get("protocolVersion", "")),
            kt_log_url=str(payload.get("ktLogUrl", "")),
            witness_url=str(payload.get("witnessUrl", "")),
            server_nonce_b64=str(payload.get("serverNonce", "")),
            relay_public_key_b64=str(payload.get("relayPublicKey", "")),
        )
        hello.validate()
        return hello


@dataclass(frozen=True)
class HTTPQServerProof:
    relay_id: str
    realm: str
    client_id: str
    client_nonce_b64: str
    server_nonce_b64: str
    relay_public_key_b64: str
    signature_b64: str

    def validate(self) -> None:
        if not self.relay_id.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing relay id")
        if not self.realm.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing realm")
        if not self.client_id.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing client id")
        if not self.client_nonce_b64.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing client nonce")
        if not self.server_nonce_b64.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing server nonce")
        if not self.relay_public_key_b64.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing relay public key")
        if not self.signature_b64.strip():
            raise HTTPQProtocolError("HTTPq server proof is missing signature")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "HTTPQServerProof":
        proof = cls(
            relay_id=str(payload.get("relayId", "")),
            realm=str(payload.get("realm", "")),
            client_id=str(payload.get("clientId", "")),
            client_nonce_b64=str(payload.get("clientNonce", "")),
            server_nonce_b64=str(payload.get("serverNonce", "")),
            relay_public_key_b64=str(payload.get("relayPublicKey", "")),
            signature_b64=str(payload.get("signature", "")),
        )
        proof.validate()
        return proof


@dataclass(frozen=True)
class KtLogRecord:
    relay_id: str
    public_key_b64: str
    algorithm: str
    created_at: str

    def validate(self) -> None:
        if not self.relay_id.strip():
            raise HTTPQProtocolError("KT record is missing relay id")
        if not self.public_key_b64.strip():
            raise HTTPQProtocolError("KT record is missing public key")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "KtLogRecord":
        record = cls(
            relay_id=str(payload.get("relayId", "")),
            public_key_b64=str(payload.get("publicKey", "")),
            algorithm=str(payload.get("algorithm", "")),
            created_at=str(payload.get("createdAt", "")),
        )
        record.validate()
        return record


@dataclass(frozen=True)
class KtSignedTreeHead:
    tree_size: int
    root_hash_b64: str
    signature_b64: str

    def validate(self) -> None:
        if self.tree_size <= 0:
            raise HTTPQProtocolError("KT signed tree head has invalid tree size")
        if not self.root_hash_b64.strip():
            raise HTTPQProtocolError("KT signed tree head is missing root hash")
        if not self.signature_b64.strip():
            raise HTTPQProtocolError("KT signed tree head is missing signature")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "KtSignedTreeHead":
        sth = cls(
            tree_size=int(payload.get("treeSize", 0)),
            root_hash_b64=str(payload.get("rootHash", "")),
            signature_b64=str(payload.get("signature", "")),
        )
        sth.validate()
        return sth


@dataclass(frozen=True)
class KtInclusionPayload:
    record: KtLogRecord
    index: int
    proof_b64: list[str]
    sth: KtSignedTreeHead
    signing_public_key_b64: str

    def validate(self) -> None:
        self.record.validate()
        self.sth.validate()
        if self.index < 0:
            raise HTTPQProtocolError("KT inclusion payload has invalid index")
        if not self.signing_public_key_b64.strip():
            raise HTTPQProtocolError("KT inclusion payload is missing signing public key")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "KtInclusionPayload":
        inclusion = cls(
            record=KtLogRecord.from_payload(payload.get("record", {})),
            index=int(payload.get("index", 0)),
            proof_b64=[str(node) for node in payload.get("proof", [])],
            sth=KtSignedTreeHead.from_payload(payload.get("sth", {})),
            signing_public_key_b64=str(payload.get("signingPublicKey", "")),
        )
        inclusion.validate()
        return inclusion


@dataclass(frozen=True)
class WitnessCheckpoint:
    log_id: str
    tree_size: int
    root_hash_b64: str
    signing_public_key_b64: str
    witness_public_key_b64: str = ""
    witness_signature_b64: str = ""

    def validate(self) -> None:
        if not self.log_id.strip():
            raise HTTPQProtocolError("witness checkpoint is missing log id")
        if self.tree_size <= 0:
            raise HTTPQProtocolError("witness checkpoint has invalid tree size")
        if not self.root_hash_b64.strip():
            raise HTTPQProtocolError("witness checkpoint is missing root hash")
        if not self.signing_public_key_b64.strip():
            raise HTTPQProtocolError("witness checkpoint is missing signing public key")
        if bool(self.witness_public_key_b64.strip()) != bool(self.witness_signature_b64.strip()):
            raise HTTPQProtocolError("witness checkpoint signature fields are incomplete")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        payload = {
            "logId": self.log_id,
            "treeSize": self.tree_size,
            "rootHash": self.root_hash_b64,
            "signingPublicKey": self.signing_public_key_b64,
        }
        if self.witness_public_key_b64.strip():
            payload["witnessPublicKey"] = self.witness_public_key_b64
            payload["witnessSignature"] = self.witness_signature_b64
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "WitnessCheckpoint":
        checkpoint = cls(
            log_id=str(payload.get("logId", "")),
            tree_size=int(payload.get("treeSize", 0)),
            root_hash_b64=str(payload.get("rootHash", "")),
            signing_public_key_b64=str(payload.get("signingPublicKey", "")),
            witness_public_key_b64=str(payload.get("witnessPublicKey", "")),
            witness_signature_b64=str(payload.get("witnessSignature", "")),
        )
        checkpoint.validate()
        return checkpoint
