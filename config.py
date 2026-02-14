"""
Configuration für Security Scanner
"""

# DNS-Timeout (in Sekunden)
DNS_TIMEOUT = 5

# HTTP/HTTPS-Timeout (in Sekunden)
HTTP_TIMEOUT = 5

# User-Agent für HTTP-Requests
USER_AGENT = "SecurityAuditScanner/1.0"

# Sicherheits-Schwellwerte
SECURITY_THRESHOLDS = {
    # Mindestanzahl von MX-Records für Redundanz
    "min_mx_records": 2,
    
    # DMARC Policy muss mindestens sein
    "min_dmarc_policy": "quarantine",  # "none" < "quarantine" < "reject"
}

# Farben für Terminal-Ausgabe
COLORS = {
    "success": "green",
    "warning": "red",
    "info": "cyan",
    "yellow": "yellow"
}

# PDF-Report Einstellungen
PDF_CONFIG = {
    "font": "helvetica",
    "title_size": 16,
    "header_size": 12,
    "body_size": 10,
    "page_width": 210,  # A4 width in mm
    "page_height": 297,  # A4 height in mm
}
