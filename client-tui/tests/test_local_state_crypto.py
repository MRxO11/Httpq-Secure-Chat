import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.local_state_crypto import (  # noqa: E402
    LocalStateCryptoError,
    load_json,
    save_json,
)


class LocalStateCryptoTests(unittest.TestCase):
    def test_round_trip_plain_json_without_passphrase(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = str(Path(tempdir) / "state.json")
            payload = {"hello": "world"}

            with patch.dict("os.environ", {}, clear=False):
                save_json(path, payload)
                restored = load_json(path)

            self.assertEqual(restored, payload)

    def test_round_trip_encrypted_json_with_passphrase(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = str(Path(tempdir) / "state.json")
            payload = {"secret": "value"}

            with patch.dict("os.environ", {"LOCAL_STATE_PASSPHRASE": "correct horse battery staple"}):
                save_json(path, payload)
                raw = Path(path).read_text(encoding="utf-8")
                self.assertIn('"cipher": "aes-256-gcm"', raw)
                restored = load_json(path)

            self.assertEqual(restored, payload)

    def test_encrypted_json_rejects_missing_or_wrong_passphrase(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = str(Path(tempdir) / "state.json")
            payload = {"secret": "value"}

            with patch.dict("os.environ", {"LOCAL_STATE_PASSPHRASE": "right-pass"}):
                save_json(path, payload)

            with patch.dict("os.environ", {}, clear=False):
                with self.assertRaises(LocalStateCryptoError):
                    load_json(path)

            with patch.dict("os.environ", {"LOCAL_STATE_PASSPHRASE": "wrong-pass"}):
                with self.assertRaises(LocalStateCryptoError):
                    load_json(path)


if __name__ == "__main__":
    unittest.main()
