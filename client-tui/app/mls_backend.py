import os


STRICT_MLS_ENV = "STRICT_MLS_REQUIRED"
MLS_PLACEHOLDER_MODE = "mls-placeholder"


class MlsBackendError(Exception):
    pass


def is_strict_mls_required() -> bool:
    raw = os.getenv(STRICT_MLS_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def ensure_mls_mode_allowed(*, mode: str, context: str) -> None:
    if mode != MLS_PLACEHOLDER_MODE:
        return
    if not is_strict_mls_required():
        return
    raise MlsBackendError(
        f"{context} requires a real MLS backend; refusing to use {MLS_PLACEHOLDER_MODE}"
    )
