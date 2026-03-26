import sys
import unittest
from pathlib import Path
from unittest.mock import patch


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.network_privacy import (  # noqa: E402
    COVER_TRAFFIC_BUCKET,
    build_cover_payload,
    cover_traffic_enabled,
    cover_traffic_interval_seconds,
    DIRECT_APPLICATION_BUCKET,
    DIRECT_CONTROL_BUCKET,
    unwrap_direct_application_payload,
    unwrap_direct_control_payload,
    wrap_direct_application_payload,
    wrap_direct_control_payload,
)


class NetworkPrivacyTests(unittest.TestCase):
    def test_direct_application_payload_is_padded_and_reversible(self):
        wrapped = wrap_direct_application_payload('{"hello":"world"}')

        self.assertGreaterEqual(len(wrapped), DIRECT_APPLICATION_BUCKET)
        self.assertEqual(
            unwrap_direct_application_payload(wrapped),
            '{"hello":"world"}',
        )

    def test_direct_control_payload_is_padded_and_reversible(self):
        wrapped = wrap_direct_control_payload({"type": "PqxdhInitAck", "ok": True})

        self.assertGreaterEqual(len(wrapped), DIRECT_CONTROL_BUCKET)
        self.assertEqual(
            unwrap_direct_control_payload(wrapped),
            {"type": "PqxdhInitAck", "ok": True},
        )

    def test_build_cover_payload_uses_fixed_bucket(self):
        wrapped = build_cover_payload()

        self.assertGreaterEqual(len(wrapped), COVER_TRAFFIC_BUCKET)

    def test_cover_traffic_defaults_are_safe(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(cover_traffic_enabled())
            self.assertEqual(cover_traffic_interval_seconds(), 12.0)


if __name__ == "__main__":
    unittest.main()
