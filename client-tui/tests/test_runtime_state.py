import sys
import unittest
from pathlib import Path
from unittest.mock import patch


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.runtime_state import runtime_state_dir, runtime_state_path, runtime_state_profile  # noqa: E402


class RuntimeStateTests(unittest.TestCase):
    def test_profile_defaults_to_chat_name(self):
        with patch.dict("os.environ", {"CHAT_NAME": "bob"}, clear=True):
            self.assertEqual(runtime_state_profile(), "bob")
            self.assertTrue(runtime_state_path("direct-identity.json").endswith("bob\\direct-identity.json"))

    def test_profile_override_wins(self):
        with patch.dict(
            "os.environ",
            {"CHAT_NAME": "bob", "CHAT_STATE_PROFILE": "bob-device-2"},
            clear=True,
        ):
            self.assertEqual(runtime_state_profile(), "bob-device-2")
            self.assertTrue(runtime_state_dir().endswith("bob-device-2"))

    def test_profile_is_sanitized(self):
        with patch.dict("os.environ", {"CHAT_STATE_PROFILE": "Bob Phone #1"}, clear=True):
            self.assertEqual(runtime_state_profile(), "Bob-Phone-1")


if __name__ == "__main__":
    unittest.main()
