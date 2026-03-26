import os


DIRECT_ONLY_ENV = "DIRECT_ONLY_MODE"
EXPERIMENTAL_ROOMS_ENV = "EXPERIMENTAL_ROOMS_ENABLED"


def is_direct_only_mode() -> bool:
    raw = os.getenv(DIRECT_ONLY_ENV, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def are_experimental_rooms_enabled() -> bool:
    raw = os.getenv(EXPERIMENTAL_ROOMS_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def room_messaging_allowed() -> bool:
    return not is_direct_only_mode() or are_experimental_rooms_enabled()
