import requests
from typing import List, Dict


def scan_leakage(domain: str) -> List[Dict]:
    """Run passive information leakage checks against a domain."""
    results: List[Dict] = []
    headers = {"User-Agent": "SecurityAuditScanner/1.0"}

    # Check 1: Header leakage on HTTPS root
    try:
        response = requests.get(
            f"https://{domain}",
            headers=headers,
            timeout=5,
        )
        server_header = response.headers.get("Server")
        powered_by_header = response.headers.get("X-Powered-By")
        if server_header or powered_by_header:
            exposed = []
            if server_header:
                exposed.append("Server")
            if powered_by_header:
                exposed.append("X-Powered-By")
            results.append(
                {
                    "check": "Header Leakage",
                    "message": f"Vorhandene Header: {', '.join(exposed)}",
                    "safe": False,
                }
            )
        else:
            results.append(
                {
                    "check": "Header Leakage",
                    "message": "Keine Server- oder Framework-Header gefunden",
                    "safe": True,
                }
            )
    except requests.exceptions.RequestException as e:
        results.append(
            {
                "check": "Header Leakage",
                "message": f"Verbindungsfehler: {str(e)}",
                "safe": False,
            }
        )

    # Check 2: security.txt availability
    try:
        response = requests.get(
            f"https://{domain}/.well-known/security.txt",
            headers=headers,
            timeout=5,
        )
        if response.status_code == 200:
            results.append(
                {
                    "check": "security.txt",
                    "message": "security.txt gefunden",
                    "safe": True,
                }
            )
        else:
            results.append(
                {
                    "check": "security.txt",
                    "message": f"Nicht gefunden (Status {response.status_code})",
                    "safe": False,
                }
            )
    except requests.exceptions.RequestException as e:
        results.append(
            {
                "check": "security.txt",
                "message": f"Verbindungsfehler: {str(e)}",
                "safe": False,
            }
        )

    return results
