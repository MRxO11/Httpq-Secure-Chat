from dataclasses import dataclass
from typing import Any


@dataclass
class DirectApplicationFrame:
    target_client_id: str
    payload: str
    target_route_token: str | None = None

    def validate(self) -> None:
        if not (self.target_client_id.strip() or (self.target_route_token or "").strip()):
            raise ValueError("direct application frame is missing target")
        if not self.payload.strip():
            raise ValueError("direct application frame is missing payload")


@dataclass
class DirectControlFrame:
    target_client_id: str
    payload: dict[str, Any]
    target_route_token: str | None = None

    def validate(self) -> None:
        if not (self.target_client_id.strip() or (self.target_route_token or "").strip()):
            raise ValueError("direct control frame is missing target")
        message_type = str(self.payload.get("type", "")).strip()
        if not message_type:
            raise ValueError("direct control frame is missing message type")
