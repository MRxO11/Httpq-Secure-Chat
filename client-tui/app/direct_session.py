import os
import hashlib
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

try:
    from .local_state_crypto import load_json as load_state_json, save_json as save_state_json
except ImportError:
    from local_state_crypto import load_json as load_state_json, save_json as save_state_json


@dataclass
class DirectSession:
    peer_client_id: str
    session_id: str
    outbound_seq: int
    highest_inbound_seq: int
    next_send_message_number: int
    next_receive_message_number: int
    send_chain_generation: int
    receive_chain_generation: int
    skipped_message_keys: list[int]
    skipped_receive_chain_secrets: dict[str, str]
    accepted_receive_message_numbers: list[int]
    dh_ratchet_turn: int
    local_ratchet_private_key_b64: str
    local_ratchet_public_key_b64: str
    remote_ratchet_public_key_b64: str | None
    local_bootstrap_private_key_b64: str
    local_bootstrap_public_key_b64: str
    remote_bootstrap_public_key_b64: str | None
    bootstrap_secret_ref: str | None
    send_chain_secret_ref: str | None
    receive_chain_secret_ref: str | None
    last_send_message_key_ref: str | None
    last_receive_message_key_ref: str | None
    bootstrap_sent: bool
    bootstrap_acked: bool


@dataclass(frozen=True)
class DirectSessionSnapshot:
    peer_client_id: str
    session_id: str
    outbound_sequence: int
    highest_inbound_sequence: int
    mode: str
    bootstrap_ready: bool
    ratchet_initialized: bool
    dh_ratchet_turn: int
    local_ratchet_public_key_b64: str | None
    remote_ratchet_public_key_b64: str | None
    send_chain_generation: int
    receive_chain_generation: int
    send_chain_key_ref: str | None
    receive_chain_key_ref: str | None
    send_chain_secret_ref: str | None
    receive_chain_secret_ref: str | None
    skipped_message_keys: int
    last_send_message_number: int | None
    last_receive_message_number: int | None
    last_send_message_key_ref: str | None
    last_receive_message_key_ref: str | None

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "peer_client_id": self.peer_client_id,
            "session_id": self.session_id,
            "outbound_sequence": self.outbound_sequence,
            "highest_inbound_sequence": self.highest_inbound_sequence,
            "mode": self.mode,
            "bootstrap_ready": self.bootstrap_ready,
            "ratchet_initialized": self.ratchet_initialized,
            "dh_ratchet_turn": self.dh_ratchet_turn,
            "local_ratchet_public_key_b64": self.local_ratchet_public_key_b64,
            "remote_ratchet_public_key_b64": self.remote_ratchet_public_key_b64,
            "send_chain_generation": self.send_chain_generation,
            "receive_chain_generation": self.receive_chain_generation,
            "send_chain_key_ref": self.send_chain_key_ref,
            "receive_chain_key_ref": self.receive_chain_key_ref,
            "skipped_message_keys": self.skipped_message_keys,
            "last_send_message_number": self.last_send_message_number,
            "last_receive_message_number": self.last_receive_message_number,
            "last_send_message_key_ref": self.last_send_message_key_ref,
            "last_receive_message_key_ref": self.last_receive_message_key_ref,
        }

    @classmethod
    def from_contract_dict(cls, payload: dict[str, object | None]) -> "DirectSessionSnapshot":
        return cls(
            peer_client_id=str(payload["peer_client_id"]),
            session_id=str(payload["session_id"]),
            outbound_sequence=int(payload["outbound_sequence"]),
            highest_inbound_sequence=int(payload["highest_inbound_sequence"]),
            mode=str(payload["mode"]),
            bootstrap_ready=bool(payload["bootstrap_ready"]),
            ratchet_initialized=bool(payload["ratchet_initialized"]),
            dh_ratchet_turn=int(payload["dh_ratchet_turn"]),
            local_ratchet_public_key_b64=payload.get("local_ratchet_public_key_b64"),  # type: ignore[arg-type]
            remote_ratchet_public_key_b64=payload.get("remote_ratchet_public_key_b64"),  # type: ignore[arg-type]
            send_chain_generation=int(payload["send_chain_generation"]),
            receive_chain_generation=int(payload["receive_chain_generation"]),
            send_chain_key_ref=payload.get("send_chain_key_ref"),  # type: ignore[arg-type]
            receive_chain_key_ref=payload.get("receive_chain_key_ref"),  # type: ignore[arg-type]
            send_chain_secret_ref=None,
            receive_chain_secret_ref=None,
            skipped_message_keys=int(payload["skipped_message_keys"]),
            last_send_message_number=(
                int(payload["last_send_message_number"])
                if payload.get("last_send_message_number") is not None
                else None
            ),
            last_receive_message_number=(
                int(payload["last_receive_message_number"])
                if payload.get("last_receive_message_number") is not None
                else None
            ),
            last_send_message_key_ref=payload.get("last_send_message_key_ref"),  # type: ignore[arg-type]
            last_receive_message_key_ref=payload.get("last_receive_message_key_ref"),  # type: ignore[arg-type]
        )


class DirectSessionStore:
    def __init__(self, path: str | None = None, max_skipped_message_keys: int | None = None) -> None:
        self.path = path or os.getenv(
            "DIRECT_SESSION_FILE",
            os.path.join(os.path.expanduser("~"), ".secure-chat", "direct-sessions.json"),
        )
        self.max_skipped_message_keys = max(
            1,
            int(os.getenv("DIRECT_MAX_SKIPPED_MESSAGE_KEYS", str(max_skipped_message_keys or 32))),
        )
        self.send_ratchet_rotation_interval = max(
            2,
            int(os.getenv("DIRECT_SEND_RATCHET_ROTATION_INTERVAL", "4")),
        )
        self._sessions = self._load()

    def get_or_create(self, peer_client_id: str, session_id: str) -> DirectSession:
        existing = self._sessions.get(peer_client_id)
        if existing is not None:
            if existing.session_id != session_id:
                existing = self._new_session(peer_client_id, session_id)
                self._sessions[peer_client_id] = existing
                self._save()
            elif not existing.local_ratchet_private_key_b64 or not existing.local_ratchet_public_key_b64:
                (
                    existing.local_ratchet_private_key_b64,
                    existing.local_ratchet_public_key_b64,
                ) = self._generate_ratchet_keypair()
                self._save()
            return existing

        created = self._new_session(peer_client_id, session_id)
        self._sessions[peer_client_id] = created
        self._save()
        return created

    def next_outbound(self, peer_client_id: str, session_id: str) -> tuple[int, int, int, bool, str]:
        session = self.get_or_create(peer_client_id, session_id)
        needs_bootstrap = not session.bootstrap_sent
        if self._should_rotate_local_send_ratchet(session, needs_bootstrap):
            self._rotate_local_send_ratchet(session)
        session.bootstrap_sent = True
        session.outbound_seq += 1
        session.send_chain_generation += 1
        message_number = session.next_send_message_number
        if session.send_chain_secret_ref is not None:
            session.last_send_message_key_ref = self._derive_message_key_ref(
                session.send_chain_secret_ref,
                message_number,
            )
        session.next_send_message_number += 1
        self._save()
        return (
            session.outbound_seq,
            session.send_chain_generation,
            message_number,
            needs_bootstrap,
            session.local_ratchet_public_key_b64,
        )

    def accept_inbound(
        self,
        peer_client_id: str,
        session_id: str,
        seq: int,
        message_number: int,
        uses_session_chain: bool,
        sender_ratchet_key_b64: str | None = None,
    ) -> tuple[bool, int, int, bool, str]:
        session = self.get_or_create(peer_client_id, session_id)
        turn_reset = self._apply_remote_ratchet_turn(session, sender_ratchet_key_b64)
        used_skipped = False
        if not uses_session_chain:
            if seq <= session.highest_inbound_seq:
                return (
                    False,
                    session.receive_chain_generation,
                    message_number,
                    used_skipped,
                    session.local_ratchet_public_key_b64,
                )
            session.highest_inbound_seq = max(session.highest_inbound_seq, seq)
            session.receive_chain_generation = seq
            session.last_receive_message_key_ref = None
            self._save()
            return (
                True,
                session.receive_chain_generation,
                message_number,
                used_skipped,
                session.local_ratchet_public_key_b64,
            )
        if message_number in session.accepted_receive_message_numbers:
            return (
                False,
                session.receive_chain_generation,
                session.next_receive_message_number,
                used_skipped,
                session.local_ratchet_public_key_b64,
            )
        if seq <= session.highest_inbound_seq:
            skipped_secret = session.skipped_receive_chain_secrets.get(str(message_number))
            if skipped_secret is None:
                return (
                    False,
                    session.receive_chain_generation,
                    session.next_receive_message_number,
                    used_skipped,
                    session.local_ratchet_public_key_b64,
                )
            session.skipped_receive_chain_secrets.pop(str(message_number), None)
            self._sync_skipped_message_keys(session)
            used_skipped = True
            session.last_receive_message_key_ref = self._derive_message_key_ref(
                skipped_secret,
                message_number,
            )
            self._mark_receive_message_accepted(session, message_number)
            self._save()
            return (
                True,
                session.receive_chain_generation,
                message_number,
                used_skipped,
                session.local_ratchet_public_key_b64,
            )

        if session.receive_chain_secret_ref is not None:
            target_secret = session.receive_chain_secret_ref
            expected_message_number = 1 if turn_reset else max(2, session.next_receive_message_number + 1)
            for skipped in range(expected_message_number, message_number):
                session.skipped_receive_chain_secrets[str(skipped)] = target_secret
                target_secret = self._advance_chain_secret(target_secret)
            session.last_receive_message_key_ref = self._derive_message_key_ref(
                target_secret,
                message_number,
            )
            self._trim_skipped_receive_cache(session)
            session.receive_chain_secret_ref = self._advance_chain_secret(target_secret)
            self._sync_skipped_message_keys(session)
        session.highest_inbound_seq = seq
        session.receive_chain_generation = seq
        session.next_receive_message_number = max(session.next_receive_message_number, message_number)
        self._mark_receive_message_accepted(session, message_number)
        self._save()
        return (
            True,
            session.receive_chain_generation,
            message_number,
            used_skipped,
            session.local_ratchet_public_key_b64,
        )

    def snapshot(self, peer_client_id: str) -> DirectSession | None:
        return self._sessions.get(peer_client_id)

    def snapshot_view(self, peer_client_id: str) -> DirectSessionSnapshot | None:
        session = self.snapshot(peer_client_id)
        if session is None:
            return None
        return DirectSessionSnapshot(
            peer_client_id=session.peer_client_id,
            session_id=session.session_id,
            outbound_sequence=session.outbound_seq,
            highest_inbound_sequence=session.highest_inbound_seq,
            mode=(
                "pqxdh-bridge-session"
                if session.bootstrap_secret_ref is not None
                else "signed-static-session"
            ),
            bootstrap_ready=session.bootstrap_sent and session.bootstrap_secret_ref is not None,
            ratchet_initialized=bool(
                session.local_ratchet_public_key_b64 and session.send_chain_secret_ref
            ),
            dh_ratchet_turn=session.dh_ratchet_turn,
            local_ratchet_public_key_b64=session.local_ratchet_public_key_b64 or None,
            remote_ratchet_public_key_b64=session.remote_ratchet_public_key_b64,
            send_chain_generation=session.send_chain_generation,
            receive_chain_generation=session.receive_chain_generation,
            send_chain_key_ref=session.send_chain_secret_ref,
            receive_chain_key_ref=session.receive_chain_secret_ref,
            send_chain_secret_ref=session.send_chain_secret_ref,
            receive_chain_secret_ref=session.receive_chain_secret_ref,
            skipped_message_keys=len(session.skipped_message_keys),
            last_send_message_number=(
                session.next_send_message_number - 1 if session.next_send_message_number > 1 else None
            ),
            last_receive_message_number=(
                session.next_receive_message_number - 1 if session.next_receive_message_number > 1 else None
            ),
            last_send_message_key_ref=session.last_send_message_key_ref,
            last_receive_message_key_ref=session.last_receive_message_key_ref,
        )

    def set_local_bootstrap_material(
        self,
        peer_client_id: str,
        session_id: str,
        private_key_b64: str,
        public_key_b64: str,
    ) -> None:
        session = self.get_or_create(peer_client_id, session_id)
        session.local_bootstrap_private_key_b64 = private_key_b64
        session.local_bootstrap_public_key_b64 = public_key_b64
        self._save()

    def set_bootstrap_secret(
        self,
        peer_client_id: str,
        session_id: str,
        remote_bootstrap_public_key_b64: str,
        secret_ref: str,
        *,
        local_is_initiator: bool,
    ) -> None:
        session = self.get_or_create(peer_client_id, session_id)
        session.remote_bootstrap_public_key_b64 = remote_bootstrap_public_key_b64
        session.bootstrap_secret_ref = secret_ref
        if local_is_initiator:
            session.send_chain_secret_ref = self._derive_chain_secret(secret_ref, "init-send")
            session.receive_chain_secret_ref = self._derive_chain_secret(secret_ref, "resp-send")
        else:
            session.send_chain_secret_ref = self._derive_chain_secret(secret_ref, "resp-send")
            session.receive_chain_secret_ref = self._derive_chain_secret(secret_ref, "init-send")
        self._save()

    def current_send_chain_secret(self, peer_client_id: str, session_id: str) -> str | None:
        return self.get_or_create(peer_client_id, session_id).send_chain_secret_ref

    def current_receive_chain_secret(self, peer_client_id: str, session_id: str) -> str | None:
        return self.get_or_create(peer_client_id, session_id).receive_chain_secret_ref

    def preview_inbound_chain_secret(
        self,
        peer_client_id: str,
        session_id: str,
        seq: int,
        message_number: int,
        uses_session_chain: bool,
        sender_ratchet_key_b64: str | None = None,
    ) -> tuple[str | None, bool]:
        session = self.get_or_create(peer_client_id, session_id)
        if not uses_session_chain:
            return None, False
        skipped_secret = session.skipped_receive_chain_secrets.get(str(message_number))
        if skipped_secret is not None:
            return skipped_secret, True
        turn_reset = bool(
            sender_ratchet_key_b64
            and session.remote_ratchet_public_key_b64 is not None
            and sender_ratchet_key_b64 != session.remote_ratchet_public_key_b64
        )
        if seq <= session.highest_inbound_seq:
            return session.receive_chain_secret_ref, False
        secret = session.receive_chain_secret_ref
        if turn_reset and session.bootstrap_secret_ref:
            secret = self._derive_ratchet_turn_secret(
                session.bootstrap_secret_ref,
                sender_ratchet_key_b64,
            )
        if secret is None:
            return None, False
        expected_message_number = 1 if turn_reset else max(2, session.next_receive_message_number + 1)
        for _ in range(expected_message_number, message_number):
            secret = self._advance_chain_secret(secret)
        return secret, False

    def advance_send_chain(self, peer_client_id: str, session_id: str) -> None:
        session = self.get_or_create(peer_client_id, session_id)
        if session.send_chain_secret_ref:
            session.send_chain_secret_ref = self._advance_chain_secret(session.send_chain_secret_ref)
            self._save()

    def advance_receive_chain(self, peer_client_id: str, session_id: str) -> None:
        session = self.get_or_create(peer_client_id, session_id)
        if session.receive_chain_secret_ref:
            session.receive_chain_secret_ref = self._advance_chain_secret(session.receive_chain_secret_ref)
            self._save()

    def mark_bootstrap_acked(self, peer_client_id: str, session_id: str) -> None:
        session = self.get_or_create(peer_client_id, session_id)
        session.bootstrap_acked = True
        self._save()

    def _new_session(self, peer_client_id: str, session_id: str) -> DirectSession:
        local_ratchet_private_key_b64, local_ratchet_public_key_b64 = self._generate_ratchet_keypair()
        return DirectSession(
            peer_client_id=peer_client_id,
            session_id=session_id,
            outbound_seq=0,
            highest_inbound_seq=0,
            next_send_message_number=1,
            next_receive_message_number=1,
            send_chain_generation=0,
            receive_chain_generation=0,
            skipped_message_keys=[],
            skipped_receive_chain_secrets={},
            accepted_receive_message_numbers=[],
            dh_ratchet_turn=0,
            local_ratchet_private_key_b64=local_ratchet_private_key_b64,
            local_ratchet_public_key_b64=local_ratchet_public_key_b64,
            remote_ratchet_public_key_b64=None,
            local_bootstrap_private_key_b64="",
            local_bootstrap_public_key_b64="",
            remote_bootstrap_public_key_b64=None,
            bootstrap_secret_ref=None,
            send_chain_secret_ref=None,
            receive_chain_secret_ref=None,
            last_send_message_key_ref=None,
            last_receive_message_key_ref=None,
            bootstrap_sent=False,
            bootstrap_acked=False,
        )

    def _load(self) -> dict[str, DirectSession]:
        if not os.path.exists(self.path):
            return {}

        raw = load_state_json(self.path)
        sessions: dict[str, DirectSession] = {}
        for peer_id, session in raw.items():
            sessions[peer_id] = DirectSession(
                peer_client_id=session["peer_client_id"],
                session_id=session["session_id"],
                outbound_seq=session.get("outbound_seq", 0),
                highest_inbound_seq=session.get("highest_inbound_seq", 0),
                next_send_message_number=session.get("next_send_message_number", 1),
                next_receive_message_number=session.get("next_receive_message_number", 1),
                send_chain_generation=session.get("send_chain_generation", 0),
                receive_chain_generation=session.get("receive_chain_generation", 0),
                skipped_message_keys=session.get("skipped_message_keys", []),
                skipped_receive_chain_secrets=session.get("skipped_receive_chain_secrets", {}),
                accepted_receive_message_numbers=session.get("accepted_receive_message_numbers", []),
                dh_ratchet_turn=session.get("dh_ratchet_turn", 0),
                local_ratchet_private_key_b64=session.get("local_ratchet_private_key_b64", ""),
                local_ratchet_public_key_b64=session.get("local_ratchet_public_key_b64", ""),
                remote_ratchet_public_key_b64=session.get("remote_ratchet_public_key_b64"),
                local_bootstrap_private_key_b64=session.get("local_bootstrap_private_key_b64", ""),
                local_bootstrap_public_key_b64=session.get("local_bootstrap_public_key_b64", ""),
                remote_bootstrap_public_key_b64=session.get("remote_bootstrap_public_key_b64"),
                bootstrap_secret_ref=session.get("bootstrap_secret_ref"),
                send_chain_secret_ref=session.get("send_chain_secret_ref"),
                receive_chain_secret_ref=session.get("receive_chain_secret_ref"),
                last_send_message_key_ref=session.get("last_send_message_key_ref"),
                last_receive_message_key_ref=session.get("last_receive_message_key_ref"),
                bootstrap_sent=session.get("bootstrap_sent", False),
                bootstrap_acked=session.get("bootstrap_acked", False),
            )
            self._trim_skipped_receive_cache(sessions[peer_id])
            self._trim_accepted_receive_cache(sessions[peer_id])
            self._sync_skipped_message_keys(sessions[peer_id])
        return sessions

    def _derive_chain_secret(self, secret_ref: str, label: str) -> str:
        return self._b64(hashlib.sha256(f"{label}|{secret_ref}".encode("utf-8")).digest())

    def _advance_chain_secret(self, secret_ref: str) -> str:
        return self._b64(hashlib.sha256(f"step|{secret_ref}".encode("utf-8")).digest())

    def _apply_remote_ratchet_turn(self, session: DirectSession, sender_ratchet_key_b64: str | None) -> bool:
        if not sender_ratchet_key_b64 or sender_ratchet_key_b64 == session.remote_ratchet_public_key_b64:
            return False
        first_remote_key = session.remote_ratchet_public_key_b64 is None
        session.remote_ratchet_public_key_b64 = sender_ratchet_key_b64
        session.dh_ratchet_turn += 1
        if first_remote_key:
            return False
        session.send_chain_generation = 0
        session.receive_chain_generation = 0
        session.next_send_message_number = 1
        session.next_receive_message_number = 1
        session.skipped_receive_chain_secrets = {}
        session.accepted_receive_message_numbers = []
        if session.bootstrap_secret_ref:
            session.receive_chain_secret_ref = self._derive_ratchet_turn_secret(
                session.bootstrap_secret_ref,
                sender_ratchet_key_b64,
            )
        self._sync_skipped_message_keys(session)
        session.local_ratchet_private_key_b64, session.local_ratchet_public_key_b64 = (
            self._generate_ratchet_keypair()
        )
        if session.bootstrap_secret_ref:
            session.send_chain_secret_ref = self._derive_ratchet_turn_secret(
                session.bootstrap_secret_ref,
                session.local_ratchet_public_key_b64,
            )
        return True

    def _sync_skipped_message_keys(self, session: DirectSession) -> None:
        session.skipped_message_keys = sorted(int(key) for key in session.skipped_receive_chain_secrets.keys())

    def _trim_skipped_receive_cache(self, session: DirectSession) -> None:
        while len(session.skipped_receive_chain_secrets) > self.max_skipped_message_keys:
            oldest_key = min(session.skipped_receive_chain_secrets.keys(), key=int)
            session.skipped_receive_chain_secrets.pop(oldest_key, None)

    def _trim_accepted_receive_cache(self, session: DirectSession) -> None:
        max_entries = max(self.max_skipped_message_keys * 2, 64)
        while len(session.accepted_receive_message_numbers) > max_entries:
            session.accepted_receive_message_numbers.pop(0)

    def _mark_receive_message_accepted(self, session: DirectSession, message_number: int) -> None:
        if message_number not in session.accepted_receive_message_numbers:
            session.accepted_receive_message_numbers.append(message_number)
            session.accepted_receive_message_numbers.sort()
            self._trim_accepted_receive_cache(session)

    def _should_rotate_local_send_ratchet(self, session: DirectSession, needs_bootstrap: bool) -> bool:
        return (
            not needs_bootstrap
            and session.bootstrap_acked
            and session.bootstrap_secret_ref is not None
            and session.send_chain_generation >= self.send_ratchet_rotation_interval
        )

    def _rotate_local_send_ratchet(self, session: DirectSession) -> None:
        session.dh_ratchet_turn += 1
        session.local_ratchet_private_key_b64, session.local_ratchet_public_key_b64 = (
            self._generate_ratchet_keypair()
        )
        session.send_chain_generation = 0
        session.next_send_message_number = 1
        session.send_chain_secret_ref = self._derive_ratchet_turn_secret(
            session.bootstrap_secret_ref,
            session.local_ratchet_public_key_b64,
        )

    def _derive_ratchet_turn_secret(self, secret_ref: str, ratchet_public_key_b64: str) -> str:
        return self._b64(
            hashlib.sha256(f"turn|{ratchet_public_key_b64}|{secret_ref}".encode("utf-8")).digest()
        )

    def _derive_message_key_ref(self, chain_secret_ref: str, message_number: int) -> str:
        return f"mk::{message_number}::{self._b64(hashlib.sha256(f'mk|{message_number}|{chain_secret_ref}'.encode('utf-8')).digest())}"


    def _generate_ratchet_keypair(self) -> tuple[str, str]:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (
            self._b64(
                private_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )
            ),
            self._b64(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        )

    def _b64(self, raw: bytes) -> str:
        import base64

        return base64.b64encode(raw).decode("ascii")

    def _save(self) -> None:
        save_state_json(
            self.path,
            {peer_id: asdict(session) for peer_id, session in self._sessions.items()},
        )
