import base64
import json
import os


DIRECT_APPLICATION_BUCKET = 2048
DIRECT_CONTROL_BUCKET = 1024
COVER_TRAFFIC_BUCKET = 512


def wrap_direct_application_payload(payload: str) -> str:
    return _wrap_payload("direct-application", payload, DIRECT_APPLICATION_BUCKET)


def unwrap_direct_application_payload(payload: str) -> str:
    unwrapped = _unwrap_payload("direct-application", payload)
    return payload if unwrapped is None else str(unwrapped)


def wrap_direct_control_payload(payload: dict) -> str:
    return _wrap_payload("direct-control", payload, DIRECT_CONTROL_BUCKET)


def unwrap_direct_control_payload(payload: str):
    unwrapped = _unwrap_payload("direct-control", payload)
    if unwrapped is None:
        return json.loads(payload)
    return unwrapped


def cover_traffic_enabled() -> bool:
    return os.getenv("ENABLE_COVER_TRAFFIC", "").strip().lower() in {"1", "true", "yes", "on"}


def cover_traffic_interval_seconds() -> float:
    raw = os.getenv("COVER_TRAFFIC_INTERVAL_SECONDS", "").strip()
    if not raw:
        return 12.0
    try:
        value = float(raw)
    except ValueError:
        return 12.0
    return value if value > 0 else 12.0


def build_cover_payload() -> str:
    token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
    return _wrap_payload("cover", {"nonce": token}, COVER_TRAFFIC_BUCKET)


def _wrap_payload(kind: str, body, bucket_size: int) -> str:
    wrapper = {
        "v": 1,
        "kind": kind,
        "body": body,
        "padding": "",
    }
    encoded = json.dumps(wrapper, separators=(",", ":"))
    if len(encoded) >= bucket_size:
        return encoded
    wrapper["padding"] = "0" * (bucket_size - len(encoded))
    return json.dumps(wrapper, separators=(",", ":"))


def _unwrap_payload(expected_kind: str, payload: str):
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError):
        return None
    if not isinstance(decoded, dict):
        return None
    if decoded.get("v") != 1 or decoded.get("kind") != expected_kind or "body" not in decoded:
        return None
    return decoded["body"]
