from dataclasses import dataclass
from typing import Callable


class PeerDirectoryError(Exception):
    pass


@dataclass(frozen=True)
class SnapshotResult:
    accepted_count: int
    rejected: list[str]


PeerValidator = Callable[[dict, str], None]


class PeerDirectory:
    def __init__(self, validator: PeerValidator) -> None:
        self._validator = validator
        self._peers: dict[str, dict] = {}

    def snapshot(self, *, peers: list[dict], room_id: str) -> SnapshotResult:
        accepted: dict[str, dict] = {}
        rejected: list[str] = []
        for peer in peers:
            client_id = str(peer.get("clientId", "")).strip()
            if not client_id:
                continue
            try:
                self._validator(peer=peer, room_id=room_id)
            except Exception as exc:
                rejected.append(f"{client_id}: {exc}")
                continue
            accepted[client_id] = peer
        self._peers = accepted
        return SnapshotResult(accepted_count=len(self._peers), rejected=rejected)

    def upsert(self, *, peer: dict, room_id: str) -> dict:
        client_id = str(peer.get("clientId", "")).strip()
        if not client_id:
            raise PeerDirectoryError("peer is missing client id")
        try:
            self._validator(peer=peer, room_id=room_id)
        except Exception as exc:
            raise PeerDirectoryError(str(exc)) from exc
        self._peers[client_id] = peer
        return peer

    def remove(self, client_id: str) -> dict | None:
        return self._peers.pop(client_id, None)

    def get(self, client_id: str) -> dict | None:
        return self._peers.get(client_id)

    def get_by_route_token(self, route_token: str) -> dict | None:
        route_token = route_token.strip()
        if not route_token:
            return None
        for peer in self._peers.values():
            if str(peer.get("directRouteToken", "")).strip() == route_token:
                return peer
        return None

    def resolve(self, handle: str) -> dict | None:
        handle = handle.strip()
        if not handle:
            return None
        direct = self.get(handle)
        if direct is not None:
            return direct

        lowered = handle.casefold()
        matches = [
            peer
            for peer in self._peers.values()
            if str(peer.get("username", "")).strip().casefold() == lowered
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise PeerDirectoryError(
                f"nickname '{handle}' matches multiple peers; use CLIENT_ID instead"
            )
        return matches[0]

    def values(self) -> list[dict]:
        return list(self._peers.values())

    def __len__(self) -> int:
        return len(self._peers)
