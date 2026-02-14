"""
Web Security Scanner Module
Prüft die Website-Sicherheit auf verschiedene Aspekte
"""

import requests
from colorama import Fore, Style
from typing import Dict, List


class WebScanner:
    """Prüft Website-Sicherheit (HTTPS, Headers, etc.)"""
    
    def __init__(self, domain: str, timeout: int = 5):
        self.domain = domain
        self.timeout = timeout
        self.results = []
        self.headers = {'User-Agent': 'SecurityAuditScanner/1.0'}
    
    def check_https_redirect(self) -> Dict:
        """Prüft, ob HTTP automatisch zu HTTPS umgeleitet wird."""
        try:
            # Versuche HTTP-URL zu erreichen mit Redirect-Verfolgung
            response = requests.get(
                f"http://{self.domain}",
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Prüfe auf Redirect (3xx Status codes)
            if 300 <= response.status_code < 400:
                location = response.headers.get('Location', '')
                if 'https://' in location:
                    return {
                        "check": "HTTPS Redirect",
                        "message": "HTTP wird auf HTTPS umgeleitet",
                        "safe": True,
                        "details": f"Status: {response.status_code}, Location: {location}"
                    }
                else:
                    return {
                        "check": "HTTPS Redirect",
                        "message": "Redirect vorhanden, aber nicht zu HTTPS",
                        "safe": False,
                        "details": f"Redirect zu: {location}"
                    }
            else:
                return {
                    "check": "HTTPS Redirect",
                    "message": "Kein automatischer HTTPS-Redirect erkannt",
                    "safe": False,
                    "details": f"HTTP Status: {response.status_code}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check": "HTTPS Redirect",
                "message": f"Fehler beim Prüfen: {str(e)}",
                "safe": False,
                "details": str(e)
            }
    
    def check_hsts_header(self) -> Dict:
        """Prüft auf HSTS (Strict-Transport-Security) Header."""
        try:
            response = requests.get(
                f"https://{self.domain}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            hsts_header = response.headers.get('Strict-Transport-Security')
            if hsts_header:
                return {
                    "check": "HSTS Header",
                    "message": "HSTS Header ist aktiviert (Verbindung ist abgesichert)",
                    "safe": True,
                    "details": f"Wert: {hsts_header}"
                }
            else:
                return {
                    "check": "HSTS Header",
                    "message": "HSTS Header fehlt! (Man-in-the-Middle Risiko)",
                    "safe": False,
                    "details": "Browser können auf HTTP downgraden"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check": "HSTS Header",
                "message": f"Konnte HTTPS-Verbindung nicht aufbauen: {str(e)}",
                "safe": False,
                "details": str(e)
            }
    
    def check_x_frame_options(self) -> Dict:
        """Prüft auf X-Frame-Options Header (Clickjacking-Schutz)."""
        try:
            response = requests.get(
                f"https://{self.domain}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            xfo_header = response.headers.get('X-Frame-Options')
            if xfo_header:
                valid_values = ['DENY', 'SAMEORIGIN', 'ALLOW-FROM']
                if any(val.upper() in xfo_header.upper() for val in valid_values):
                    return {
                        "check": "X-Frame-Options",
                        "message": "X-Frame-Options Header ist aktiviert (Clickjacking-Schutz)",
                        "safe": True,
                        "details": f"Wert: {xfo_header}"
                    }
                else:
                    return {
                        "check": "X-Frame-Options",
                        "message": "X-Frame-Options Header vorhanden, aber ungültiger Wert",
                        "safe": False,
                        "details": f"Wert: {xfo_header}"
                    }
            else:
                return {
                    "check": "X-Frame-Options",
                    "message": "X-Frame-Options Header fehlt! (Clickjacking möglich)",
                    "safe": False,
                    "details": "Website kann in iframes eingebettet werden"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check": "X-Frame-Options",
                "message": f"Fehler beim Prüfen: {str(e)}",
                "safe": False,
                "details": str(e)
            }
    
    def check_csp_header(self) -> Dict:
        """Prüft auf Content-Security-Policy Header (XSS-Schutz)."""
        try:
            response = requests.get(
                f"https://{self.domain}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            # Prüfe sowohl Content-Security-Policy als auch Content-Security-Policy-Report-Only
            csp_header = response.headers.get('Content-Security-Policy')
            csp_report_only = response.headers.get('Content-Security-Policy-Report-Only')
            
            if csp_header:
                return {
                    "check": "Content-Security-Policy",
                    "message": "CSP Header ist aktiviert (XSS-Schutz aktiv)",
                    "safe": True,
                    "details": f"Wert: {csp_header[:100]}..."
                }
            elif csp_report_only:
                return {
                    "check": "Content-Security-Policy",
                    "message": "CSP im Report-Only Modus (schwächerer Schutz)",
                    "safe": True,
                    "details": f"Wert: {csp_report_only[:100]}..."
                }
            else:
                return {
                    "check": "Content-Security-Policy",
                    "message": "CSP Header fehlt! (Website ist anfällig für XSS-Angriffe)",
                    "safe": False,
                    "details": "Keine Schutzrichtlinien für inline Scripts definiert"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check": "Content-Security-Policy",
                "message": f"Fehler beim Prüfen: {str(e)}",
                "safe": False,
                "details": str(e)
            }
    
    def check_server_leakage(self) -> Dict:
        """Prüft, ob der Server Header zu viel Information verrät."""
        try:
            response = requests.get(
                f"https://{self.domain}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            server_header = response.headers.get('Server')
            if not server_header:
                return {
                    "check": "Server Header Leakage",
                    "message": "Server Header ist nicht vorhanden (Excellent!)",
                    "safe": True,
                    "details": "Keine Serverinformationen preisgegeben"
                }
            
            # Prüfe auf zu detaillierte Informationen
            dangerous_keywords = ['Apache', 'nginx', 'Microsoft-IIS', 'Tomcat', 'PHP', 'Ubuntu', 'Debian', 'CentOS']
            has_dangerous_info = any(keyword in server_header for keyword in dangerous_keywords)
            
            if has_dangerous_info:
                return {
                    "check": "Server Header Leakage",
                    "message": f"Server verrät zu viele Informationen! (Exploits können gezielt werden)",
                    "safe": False,
                    "details": f"Server Header: {server_header}"
                }
            else:
                # Header existiert, verrät aber nicht zu viel
                return {
                    "check": "Server Header Leakage",
                    "message": "Server Header vorhanden, aber nicht zu detailliert",
                    "safe": True,
                    "details": f"Server Header: {server_header}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check": "Server Header Leakage",
                "message": f"Fehler beim Prüfen: {str(e)}",
                "safe": False,
                "details": str(e)
            }
    
    def scan(self) -> List[Dict]:
        """Führt alle Web-Sicherheitschecks durch."""
        print(f"\n{Fore.CYAN}--- WEB SECURITY SCAN: {self.domain} ---{Style.RESET_ALL}")
        
        checks = [
            self.check_https_redirect,
            self.check_hsts_header,
            self.check_x_frame_options,
            self.check_csp_header,
            self.check_server_leakage
        ]
        
        self.results = []
        for check in checks:
            result = check()
            self.results.append(result)
            
            # Ausgabe mit Farben
            if result['safe']:
                status = f"[{Fore.GREEN}OK{Style.RESET_ALL}]"
            else:
                status = f"[{Fore.RED}WARNUNG{Style.RESET_ALL}]"
            
            print(f"{status} {result['check']}: {result['message']}")
        
        return self.results
