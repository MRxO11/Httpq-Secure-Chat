from dataclasses import dataclass
from typing import Any


class RoomControlError(Exception):
    pass


@dataclass(frozen=True)
class RoomProposalMessage:
    room_id: str
    proposal_id: str
    proposal_kind: str
    sender_client_id: str
    target_client_id: str | None
    mode: str

    def validate(self) -> None:
        if not self.room_id.strip():
            raise RoomControlError("room proposal is missing room id")
        if not self.proposal_id.strip():
            raise RoomControlError("room proposal is missing proposal id")
        if not self.proposal_kind.strip():
            raise RoomControlError("room proposal is missing proposal kind")
        if not self.sender_client_id.strip():
            raise RoomControlError("room proposal is missing sender client id")
        if not self.mode.strip():
            raise RoomControlError("room proposal is missing mode")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "type": "RoomProposal",
            "roomId": self.room_id,
            "proposalId": self.proposal_id,
            "proposalKind": self.proposal_kind,
            "senderClientId": self.sender_client_id,
            "targetClientId": self.target_client_id,
            "mode": self.mode,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RoomProposalMessage":
        message = cls(
            room_id=str(payload.get("roomId", "")),
            proposal_id=str(payload.get("proposalId", "")),
            proposal_kind=str(payload.get("proposalKind", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            target_client_id=(
                str(payload["targetClientId"])
                if payload.get("targetClientId") is not None
                else None
            ),
            mode=str(payload.get("mode", "")),
        )
        message.validate()
        return message


@dataclass(frozen=True)
class RoomCommitMessage:
    room_id: str
    epoch: int
    epoch_key_ref: str
    sender_client_id: str
    mode: str
    proposal_ids: list[str]

    def validate(self) -> None:
        if not self.room_id.strip():
            raise RoomControlError("room commit is missing room id")
        if self.epoch <= 0:
            raise RoomControlError("room commit must carry a positive epoch")
        if not self.epoch_key_ref.strip():
            raise RoomControlError("room commit is missing epoch key ref")
        if not self.sender_client_id.strip():
            raise RoomControlError("room commit is missing sender client id")
        if not self.mode.strip():
            raise RoomControlError("room commit is missing mode")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "type": "RoomCommit",
            "roomId": self.room_id,
            "epoch": self.epoch,
            "epochKeyRef": self.epoch_key_ref,
            "senderClientId": self.sender_client_id,
            "mode": self.mode,
            "proposalIds": self.proposal_ids,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RoomCommitMessage":
        message = cls(
            room_id=str(payload.get("roomId", "")),
            epoch=int(payload.get("epoch", 0)),
            epoch_key_ref=str(payload.get("epochKeyRef", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            mode=str(payload.get("mode", "")),
            proposal_ids=[str(item) for item in payload.get("proposalIds", [])],
        )
        message.validate()
        return message


@dataclass(frozen=True)
class RoomWelcomeMessage:
    room_id: str
    epoch: int
    epoch_key_ref: str
    sender_client_id: str
    recipient_client_id: str
    mode: str

    def validate(self) -> None:
        if not self.room_id.strip():
            raise RoomControlError("room welcome is missing room id")
        if self.epoch <= 0:
            raise RoomControlError("room welcome must carry a positive epoch")
        if not self.epoch_key_ref.strip():
            raise RoomControlError("room welcome is missing epoch key ref")
        if not self.sender_client_id.strip():
            raise RoomControlError("room welcome is missing sender client id")
        if not self.recipient_client_id.strip():
            raise RoomControlError("room welcome is missing recipient client id")
        if not self.mode.strip():
            raise RoomControlError("room welcome is missing mode")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "type": "RoomWelcome",
            "roomId": self.room_id,
            "epoch": self.epoch,
            "epochKeyRef": self.epoch_key_ref,
            "senderClientId": self.sender_client_id,
            "recipientClientId": self.recipient_client_id,
            "mode": self.mode,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RoomWelcomeMessage":
        message = cls(
            room_id=str(payload.get("roomId", "")),
            epoch=int(payload.get("epoch", 0)),
            epoch_key_ref=str(payload.get("epochKeyRef", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            recipient_client_id=str(payload.get("recipientClientId", "")),
            mode=str(payload.get("mode", "")),
        )
        message.validate()
        return message


@dataclass(frozen=True)
class RoomEpochUpdateMessage:
    room_id: str
    epoch: int
    epoch_key_ref: str
    sender_client_id: str
    mode: str

    def validate(self) -> None:
        if not self.room_id.strip():
            raise RoomControlError("room epoch update is missing room id")
        if self.epoch <= 0:
            raise RoomControlError("room epoch update must carry a positive epoch")
        if not self.epoch_key_ref.strip():
            raise RoomControlError("room epoch update is missing epoch key ref")
        if not self.sender_client_id.strip():
            raise RoomControlError("room epoch update is missing sender client id")
        if not self.mode.strip():
            raise RoomControlError("room epoch update is missing mode")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "type": "RoomEpochUpdate",
            "roomId": self.room_id,
            "epoch": self.epoch,
            "epochKeyRef": self.epoch_key_ref,
            "senderClientId": self.sender_client_id,
            "mode": self.mode,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RoomEpochUpdateMessage":
        message = cls(
            room_id=str(payload.get("roomId", "")),
            epoch=int(payload.get("epoch", 0)),
            epoch_key_ref=str(payload.get("epochKeyRef", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            mode=str(payload.get("mode", "")),
        )
        message.validate()
        return message


RoomControlMessage = (
    RoomProposalMessage | RoomCommitMessage | RoomWelcomeMessage | RoomEpochUpdateMessage
)


@dataclass(frozen=True)
class PortableRoomControlEvent:
    room_id: str
    message_type: str
    mode: str
    epoch: int
    epoch_key_ref: str | None
    epoch_secret_ref: str | None
    commit_secret_ref: str | None
    welcome_secret_ref: str | None
    application_secret_ref: str | None

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "room_id": self.room_id,
            "message_type": self.message_type,
            "mode": self.mode,
            "epoch": self.epoch,
            "epoch_key_ref": self.epoch_key_ref,
            "epoch_secret_ref": self.epoch_secret_ref,
            "commit_secret_ref": self.commit_secret_ref,
            "welcome_secret_ref": self.welcome_secret_ref,
            "application_secret_ref": self.application_secret_ref,
        }

    @classmethod
    def from_contract_dict(
        cls,
        payload: dict[str, object | None],
    ) -> "PortableRoomControlEvent":
        return cls(
            room_id=str(payload["room_id"]),
            message_type=str(payload["message_type"]),
            mode=str(payload["mode"]),
            epoch=int(payload["epoch"]),
            epoch_key_ref=payload.get("epoch_key_ref"),  # type: ignore[arg-type]
            epoch_secret_ref=payload.get("epoch_secret_ref"),  # type: ignore[arg-type]
            commit_secret_ref=payload.get("commit_secret_ref"),  # type: ignore[arg-type]
            welcome_secret_ref=payload.get("welcome_secret_ref"),  # type: ignore[arg-type]
            application_secret_ref=payload.get("application_secret_ref"),  # type: ignore[arg-type]
        )

    @classmethod
    def from_room_control_plan(cls, plan: object) -> "PortableRoomControlEvent":
        return cls.from_contract_dict(plan.to_contract_dict())  # type: ignore[attr-defined]


def parse_room_control_message(payload: Any) -> RoomControlMessage:
    if not isinstance(payload, dict):
        raise RoomControlError("room control payload must be an object")

    message_type = payload.get("type")
    if message_type == "RoomProposal":
        return RoomProposalMessage.from_payload(payload)
    if message_type == "RoomCommit":
        return RoomCommitMessage.from_payload(payload)
    if message_type == "RoomWelcome":
        return RoomWelcomeMessage.from_payload(payload)
    if message_type == "RoomEpochUpdate":
        return RoomEpochUpdateMessage.from_payload(payload)
    raise RoomControlError(
        f"unsupported room control message type: {payload.get('type', 'unknown')}"
    )
