import json
import os
import base64
from dataclasses import asdict, dataclass
from hashlib import sha256


class RoomStateError(Exception):
    pass


@dataclass
class RoomState:
    room_id: str
    mode: str
    epoch: int
    epoch_key_ref: str | None
    epoch_secret_ref: str | None
    commit_secret_ref: str | None
    welcome_secret_ref: str | None
    application_secret_ref: str | None
    member_count: int
    pending_commit: bool
    last_proposal_id: str | None
    room_key_present: bool


@dataclass(frozen=True)
class RoomStateSnapshot:
    room_id: str
    mode: str
    epoch: int
    epoch_key_ref: str | None
    epoch_secret_ref: str | None
    commit_secret_ref: str | None
    welcome_secret_ref: str | None
    application_secret_ref: str | None
    member_count: int
    pending_commit: bool
    last_proposal_id: str | None
    room_key_present: bool

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "room_id": self.room_id,
            "mode": self.mode,
            "epoch": self.epoch,
            "epoch_key_ref": self.epoch_key_ref,
            "epoch_secret_ref": self.epoch_secret_ref,
            "commit_secret_ref": self.commit_secret_ref,
            "welcome_secret_ref": self.welcome_secret_ref,
            "application_secret_ref": self.application_secret_ref,
            "member_count": self.member_count,
            "pending_commit": self.pending_commit,
            "last_proposal_id": self.last_proposal_id,
            "room_key_present": self.room_key_present,
        }

    @classmethod
    def from_contract_dict(cls, payload: dict[str, object | None]) -> "RoomStateSnapshot":
        return cls(
            room_id=str(payload["room_id"]),
            mode=str(payload["mode"]),
            epoch=int(payload["epoch"]),
            epoch_key_ref=payload.get("epoch_key_ref"),  # type: ignore[arg-type]
            epoch_secret_ref=payload.get("epoch_secret_ref"),  # type: ignore[arg-type]
            commit_secret_ref=payload.get("commit_secret_ref"),  # type: ignore[arg-type]
            welcome_secret_ref=payload.get("welcome_secret_ref"),  # type: ignore[arg-type]
            application_secret_ref=payload.get("application_secret_ref"),  # type: ignore[arg-type]
            member_count=int(payload["member_count"]),
            pending_commit=bool(payload["pending_commit"]),
            last_proposal_id=payload.get("last_proposal_id"),  # type: ignore[arg-type]
            room_key_present=bool(payload["room_key_present"]),
        )


class RoomStateStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv(
            "ROOM_STATE_FILE",
            os.path.join(os.getcwd(), ".local", "room-state.json"),
        )
        self._rooms = self._load()

    def ensure_room(self, room_id: str) -> RoomState:
        room_id = (room_id or "lobby").strip() or "lobby"
        state = self._rooms.get(room_id)
        if state is None:
            state = RoomState(
                room_id=room_id,
                mode="room-aes-256-gcm+scrypt",
                epoch=0,
                epoch_key_ref=None,
                epoch_secret_ref=None,
                commit_secret_ref=None,
                welcome_secret_ref=None,
                application_secret_ref=None,
                member_count=0,
                pending_commit=False,
                last_proposal_id=None,
                room_key_present=False,
            )
            self._rooms[room_id] = state
            self._save()
        return state

    def set_room_key_present(self, room_id: str, present: bool) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        state.room_key_present = present
        if present and state.epoch == 0:
            state.epoch = 1
            state.epoch_key_ref = f"room-epoch::{state.room_id}::{state.epoch}"
        self._ensure_epoch_secret_ref(state)
        self._save()
        return self.snapshot(room_id)

    def record_members(self, room_id: str, member_count: int) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        state.member_count = max(0, member_count)
        self._save()
        return self.snapshot(room_id)

    def advance_epoch(self, room_id: str, mode: str | None = None) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        if mode:
            state.mode = mode
        state.epoch += 1
        state.epoch_key_ref = f"room-epoch::{state.room_id}::{state.epoch}"
        state.epoch_secret_ref = None
        state.commit_secret_ref = None
        state.welcome_secret_ref = None
        state.application_secret_ref = None
        state.pending_commit = False
        state.last_proposal_id = None
        self._ensure_epoch_secret_ref(state)
        self._save()
        return self.snapshot(room_id)

    def mark_pending_commit(
        self,
        room_id: str,
        *,
        proposal_id: str,
        mode: str,
    ) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        state.mode = mode
        state.pending_commit = True
        state.last_proposal_id = proposal_id
        self._ensure_epoch_secret_ref(state)
        self._save()
        return self.snapshot(room_id)

    def apply_remote_epoch(
        self,
        room_id: str,
        *,
        epoch: int,
        epoch_key_ref: str,
        mode: str,
    ) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        if epoch == state.epoch and state.epoch_key_ref is not None:
            if state.epoch_key_ref != epoch_key_ref or state.mode != mode:
                raise RoomStateError(
                    "conflicting room epoch update for current epoch"
                )
        if epoch >= state.epoch:
            state.mode = mode
            state.epoch = epoch
            state.epoch_key_ref = epoch_key_ref
            state.epoch_secret_ref = None
            state.commit_secret_ref = None
            state.welcome_secret_ref = None
            state.application_secret_ref = None
            state.pending_commit = False
            state.last_proposal_id = None
            self._ensure_epoch_secret_ref(state)
            self._save()
        return self.snapshot(room_id)

    def snapshot(self, room_id: str) -> RoomStateSnapshot:
        state = self.ensure_room(room_id)
        return RoomStateSnapshot(
            room_id=state.room_id,
            mode=state.mode,
            epoch=state.epoch,
            epoch_key_ref=state.epoch_key_ref,
            epoch_secret_ref=state.epoch_secret_ref,
            commit_secret_ref=state.commit_secret_ref,
            welcome_secret_ref=state.welcome_secret_ref,
            application_secret_ref=state.application_secret_ref,
            member_count=state.member_count,
            pending_commit=state.pending_commit,
            last_proposal_id=state.last_proposal_id,
            room_key_present=state.room_key_present,
        )

    def _load(self) -> dict[str, RoomState]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        rooms = {
            room_id: RoomState(
                **(
                    {
                        "last_proposal_id": None,
                        "epoch_secret_ref": None,
                        "commit_secret_ref": None,
                        "welcome_secret_ref": None,
                        "application_secret_ref": None,
                    }
                    | state_payload
                )
            )
            for room_id, state_payload in payload.items()
        }
        for state in rooms.values():
            self._ensure_epoch_secret_ref(state)
        return rooms

    def _save(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                {room_id: asdict(state) for room_id, state in self._rooms.items()},
                handle,
                indent=2,
                sort_keys=True,
            )

    def _ensure_epoch_secret_ref(self, state: RoomState) -> None:
        if state.epoch <= 0:
            state.epoch_secret_ref = None
            state.commit_secret_ref = None
            state.welcome_secret_ref = None
            state.application_secret_ref = None
            return
        if not state.epoch_key_ref:
            return
        if not state.epoch_secret_ref:
            state.epoch_secret_ref = self._derive_secret_ref(
                "group-epoch-secret/v1",
                "ges::",
                state.room_id,
                state.epoch_key_ref,
                str(state.epoch),
                self._mode_label(state.mode),
            )
        if not state.commit_secret_ref:
            state.commit_secret_ref = self._derive_secret_ref(
                "group-commit-secret/v1",
                "gcs::",
                state.room_id,
                state.epoch_secret_ref,
                state.epoch_key_ref,
                str(state.epoch),
                self._mode_label(state.mode),
            )
        if not state.welcome_secret_ref:
            state.welcome_secret_ref = self._derive_secret_ref(
                "group-welcome-secret/v1",
                "gws::",
                state.room_id,
                state.commit_secret_ref,
                str(state.epoch),
                self._mode_label(state.mode),
            )
        if not state.application_secret_ref:
            state.application_secret_ref = self._derive_secret_ref(
                "group-application-secret/v1",
                "gas::",
                state.room_id,
                state.welcome_secret_ref,
                str(state.epoch),
                self._mode_label(state.mode),
            )

    def _mode_label(self, mode: str) -> str:
        return "mls" if mode == "mls-placeholder" else "placeholder"

    def _derive_secret_ref(self, label: str, prefix: str, *parts: str) -> str:
        hasher = sha256()
        hasher.update(label.encode("utf-8"))
        for part in parts:
            hasher.update(part.encode("utf-8"))
            hasher.update(b"|")
        return prefix + base64.b64encode(hasher.digest()).decode("ascii")
