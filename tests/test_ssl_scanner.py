import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from modules.ssl_scanner import scan_ssl


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        if tz is not None:
            return cls(2026, 2, 15, tzinfo=timezone.utc)
        return cls(2026, 2, 15)


def _make_context_manager(obj: MagicMock) -> MagicMock:
    manager = MagicMock()
    manager.__enter__.return_value = obj
    manager.__exit__.return_value = None
    return manager


class TestSSLScanner(unittest.TestCase):
    def test_valid_cert_is_safe(self):
        cert = {"notAfter": "Mar 27 00:00:00 2026 GMT"}
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert
        mock_ssock_manager = _make_context_manager(mock_ssock)

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssock_manager

        mock_sock = MagicMock()
        mock_sock_manager = _make_context_manager(mock_sock)

        with patch("modules.ssl_scanner.socket.create_connection", return_value=mock_sock_manager), patch(
            "modules.ssl_scanner.ssl.create_default_context", return_value=mock_context
        ), patch("modules.ssl_scanner.datetime", FixedDateTime):
            results = scan_ssl("example.com")

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["safe"])
        self.assertEqual(results[0]["message"], "Noch 40 Tage")

    def test_near_expiry_is_not_safe(self):
        cert = {"notAfter": "Feb 25 00:00:00 2026 GMT"}
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert
        mock_ssock_manager = _make_context_manager(mock_ssock)

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssock_manager

        mock_sock = MagicMock()
        mock_sock_manager = _make_context_manager(mock_sock)

        with patch("modules.ssl_scanner.socket.create_connection", return_value=mock_sock_manager), patch(
            "modules.ssl_scanner.ssl.create_default_context", return_value=mock_context
        ), patch("modules.ssl_scanner.datetime", FixedDateTime):
            results = scan_ssl("example.com")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["safe"])
        self.assertEqual(results[0]["message"], "Noch 10 Tage")

    def test_no_https_returns_error(self):
        with patch(
            "modules.ssl_scanner.socket.create_connection", side_effect=ConnectionRefusedError
        ):
            results = scan_ssl("example.com")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["safe"])
        self.assertEqual(results[0]["message"], "Kein HTTPS verfugbar")


if __name__ == "__main__":
    unittest.main()
