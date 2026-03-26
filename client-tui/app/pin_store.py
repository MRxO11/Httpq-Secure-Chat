import os
from dataclasses import asdict, dataclass

try:
    from .local_state_crypto import load_json as load_state_json, save_json as save_state_json
except ImportError:
    from local_state_crypto import load_json as load_state_json, save_json as save_state_json


@dataclass
class RelayPin:
    relay_id: str
    realm: str
    public_key_b64: str


class PinStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv(
            "RELAY_PIN_FILE",
            os.path.join(os.path.expanduser("~"), ".secure-chat", "relay-pins.json"),
        )
        self._pins = self._load()

    def get(self, relay_id: str) -> RelayPin | None:
        data = self._pins.get(relay_id)
        if data is None:
            return None
        return RelayPin(**data)

    def save(self, pin: RelayPin) -> None:
        self._pins[pin.relay_id] = asdict(pin)
        save_state_json(self.path, self._pins)

    def _load(self) -> dict[str, dict]:
        if not os.path.exists(self.path):
            return {}
        return load_state_json(self.path)
