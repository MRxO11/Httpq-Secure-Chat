import os


HIDE_UI_METADATA_ENV = "HIDE_UI_METADATA"
SHOW_PROTOCOL_DETAILS_ENV = "SHOW_PROTOCOL_DETAILS"


def hide_ui_metadata() -> bool:
    raw = os.getenv(HIDE_UI_METADATA_ENV, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def show_protocol_details() -> bool:
    raw = os.getenv(SHOW_PROTOCOL_DETAILS_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}
