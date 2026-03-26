import json


def peer_announcement_bytes(
    *,
    client_id: str,
    username: str,
    room_id: str,
    encryption_key_b64: str,
    signing_key_b64: str,
) -> bytes:
    return "\n".join(
        [
            "PEER/1",
            room_id,
            client_id,
            username,
            encryption_key_b64,
            signing_key_b64,
        ]
    ).encode("utf-8")


def direct_message_bytes(*, room_id: str, target_client_id: str, envelope: dict) -> bytes:
    canonical = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    return "\n".join(["DM/1", room_id, target_client_id, canonical]).encode("utf-8")


def bootstrap_message_bytes(*, payload: dict) -> bytes:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return "\n".join(["BOOTSTRAP/1", canonical]).encode("utf-8")
