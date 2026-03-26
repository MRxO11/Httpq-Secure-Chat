from dataclasses import dataclass


@dataclass(frozen=True)
class TrafficEventMetadata:
    conversation_kind: str
    transport_kind: str
    mode: str
    room_id: str | None = None
    peer_client_id: str | None = None
    sequence: int | None = None
    ratchet_generation: int | None = None
    message_number: int | None = None
    message_key_ref: str | None = None


@dataclass(frozen=True)
class TrafficMessage:
    metadata: TrafficEventMetadata
    display_name: str
    plaintext: str
    outgoing: bool = False
    used_skipped_key: bool = False

    def render(self) -> str:
        if self.metadata.conversation_kind == "room":
            if self.outgoing:
                return (
                    f"[room {self.metadata.mode} {self.metadata.room_id} -> room] {self.plaintext}"
                )
            return f"[room {self.metadata.mode} {self.metadata.room_id}] {self.display_name}: {self.plaintext}"

        if self.metadata.conversation_kind == "direct":
            skipped_note = " skipped-key" if self.used_skipped_key else ""
            key_note = (
                f" key={self.metadata.message_key_ref}"
                if self.metadata.message_key_ref
                else ""
            )
            if self.outgoing:
                return (
                    f"[dm {self.metadata.mode} seq={self.metadata.sequence} "
                    f"msg={self.metadata.message_number} "
                    f"ratchet={self.metadata.ratchet_generation}{key_note} -> "
                    f"{self.display_name}] {self.plaintext}"
                )
            return (
                f"[dm {self.metadata.mode} seq={self.metadata.sequence} "
                f"msg={self.metadata.message_number} "
                f"ratchet={self.metadata.ratchet_generation}{key_note}{skipped_note}] "
                f"{self.display_name}: {self.plaintext}"
            )

        return f"{self.display_name}: {self.plaintext}"


@dataclass(frozen=True)
class RuntimeNotice:
    kind: str
    message: str

    def render(self) -> str:
        return self.message
