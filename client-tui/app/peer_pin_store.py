import json
import os
from dataclasses import asdict, dataclass

try:
    from .local_state_crypto import load_json as load_state_json, save_json as save_state_json
except ImportError:
    from local_state_crypto import load_json as load_state_json, save_json as save_state_json


@dataclass
class PeerPin:
    room_id: str
    username: str
    encryption_key_b64: str
    signing_key_b64: str


class PeerPinStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv(
            "PEER_PIN_FILE",
            os.path.join(os.getcwd(), ".local", "peer-pins.json"),
        )
        self._pins = self._load()

    def get(self, *, room_id: str, username: str) -> PeerPin | None:
        data = self._pins.get(self._key(room_id=room_id, username=username))
        if data is None:
            return None
        return PeerPin(**data)

    def save(self, pin: PeerPin) -> None:
        self._pins[self._key(room_id=pin.room_id, username=pin.username)] = asdict(pin)
        self._persist()

    def remove(self, *, room_id: str, username: str) -> PeerPin | None:
        data = self._pins.pop(self._key(room_id=room_id, username=username), None)
        if data is None:
            return None
        self._persist()
        return PeerPin(**data)

    def _persist(self) -> None:
        save_state_json(self.path, self._pins)

    def _load(self) -> dict[str, dict]:
        if not os.path.exists(self.path):
            return {}
        return load_state_json(self.path)

    @staticmethod
    def _key(*, room_id: str, username: str) -> str:
        return f"{room_id}::{username.casefold()}"
