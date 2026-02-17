import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any


def scan_ssl(domain: str) -> List[Dict[str, Any]]:
    """Check SSL certificate validity for a domain over port 443."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            return [
                {
                    "check": "SSL Gültigkeit",
                    "message": "Zertifikatdatum fehlt",
                    "safe": False,
                }
            ]

        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days
        safe = days_left >= 30
        return [
            {
                "check": "SSL Gültigkeit",
                "message": f"Noch {days_left} Tage",
                "safe": safe,
            }
        ]
    except (socket.gaierror, ConnectionRefusedError, TimeoutError, ssl.SSLError, OSError):
        return [
            {
                "check": "SSL Gültigkeit",
                "message": "Kein HTTPS verfugbar",
                "safe": False,
            }
        ]
