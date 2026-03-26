import os
import re


def runtime_state_profile(chat_name: str | None = None) -> str:
    explicit = (os.getenv("CHAT_STATE_PROFILE", "") or "").strip()
    if explicit:
        return _sanitize_profile(explicit)
    candidate = (chat_name or os.getenv("CHAT_NAME", "") or "anonymous").strip()
    return _sanitize_profile(candidate or "anonymous")


def runtime_state_dir(chat_name: str | None = None) -> str:
    root = os.getenv("CHAT_STATE_ROOT", os.path.join(os.getcwd(), ".local", "clients"))
    return os.path.join(root, runtime_state_profile(chat_name))


def runtime_state_path(filename: str, chat_name: str | None = None) -> str:
    return os.path.join(runtime_state_dir(chat_name), filename)


def _sanitize_profile(value: str) -> str:
    collapsed = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return collapsed or "anonymous"
