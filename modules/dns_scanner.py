"""
DNS Security Scanner Module
Prüft die E-Mail-Infrastruktur (SPF, DMARC, etc.)
"""

import dns.resolver
import dns.rdatatype
from colorama import Fore, Style
from typing import Dict, List


class DNSScanner:
    """Prüft E-Mail-Sicherheit via DNS-Records (SPF, DMARC, etc.)"""
    
    def __init__(self, domain: str, timeout: int = 5):
        self.domain = domain
        self.timeout = timeout
        self.results = []
        # DNS-Resolver mit Timeout konfigurieren
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
    
    def check_spf_record(self) -> Dict:
        """Prüft auf SPF (Sender Policy Framework) Record."""
        try:
            # Versuche TXT-Records abzurufen
            answers = self.resolver.resolve(self.domain, 'TXT', lifetime=self.timeout)
            
            # Durchsuche alle TXT-Records nach SPF
            spf_record = None
            for rdata in answers:
                # TXT Records können mehrere Strings enthalten
                txt_string = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if 'v=spf1' in txt_string:
                    spf_record = txt_string
                    break
            
            if spf_record:
                return {
                    "check": "SPF Record",
                    "message": "SPF Record gefunden (Spam-/Phishing-Schutz aktiv)",
                    "safe": True,
                    "details": f"SPF: {spf_record[:80]}{'...' if len(spf_record) > 80 else ''}"
                }
            else:
                return {
                    "check": "SPF Record",
                    "message": "Kein SPF Record gefunden! (Phishing/Spoofing Gefahr)",
                    "safe": False,
                    "details": "Jeder kann im Namen dieser Domain E-Mails versenden"
                }
        
        except dns.resolver.NXDOMAIN:
            return {
                "check": "SPF Record",
                "message": "Domain existiert nicht im DNS",
                "safe": False,
                "details": "NXDOMAIN - ungültige Domain"
            }
        except dns.resolver.NoAnswer:
            return {
                "check": "SPF Record",
                "message": "Keine TXT-Records vorhanden",
                "safe": False,
                "details": "Domain hat keine TXT-Records definiert"
            }
        except dns.exception.Timeout:
            return {
                "check": "SPF Record",
                "message": f"DNS-Abfrage Timeout",
                "safe": False,
                "details": f"Server antwortet nicht innerhalb von {self.timeout}s"
            }
        except Exception as e:
            return {
                "check": "SPF Record",
                "message": f"Fehler beim Abrufen des SPF Records",
                "safe": False,
                "details": str(e)
            }
    
    def check_dmarc_record(self) -> Dict:
        """Prüft auf DMARC (Domain-based Message Authentication, Reporting & Conformance)."""
        try:
            # DMARC ist immer unter _dmarc.[domain]
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
            
            # Durchsuche nach DMARC Record
            dmarc_record = None
            for rdata in answers:
                txt_string = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if 'v=DMARC1' in txt_string:
                    dmarc_record = txt_string
                    break
            
            if dmarc_record:
                # Prüfe auf Policy (p=reject ist am sichersten)
                policy = "unknown"
                if 'p=reject' in dmarc_record:
                    policy = "reject (sicherste Option)"
                elif 'p=quarantine' in dmarc_record:
                    policy = "quarantine (Spam-Ordner)"
                elif 'p=none' in dmarc_record:
                    policy = "none (nur Monitoring)"
                
                return {
                    "check": "DMARC Record",
                    "message": f"DMARC Record gefunden (CEO-Fraud Schutz mit Policy: {policy})",
                    "safe": True,
                    "details": f"DMARC: {dmarc_record[:80]}{'...' if len(dmarc_record) > 80 else ''}"
                }
            else:
                return {
                    "check": "DMARC Record",
                    "message": "DMARC Record vorhanden aber ungültig",
                    "safe": False,
                    "details": f"_dmarc.{self.domain} hat keine DMARC-Policy"
                }
        
        except dns.resolver.NXDOMAIN:
            return {
                "check": "DMARC Record",
                "message": "DMARC Record fehlt! (CEO-Fraud möglich)",
                "safe": False,
                "details": f"_dmarc.{self.domain} existiert nicht - keine DMARC Protection"
            }
        except dns.resolver.NoAnswer:
            return {
                "check": "DMARC Record",
                "message": "DMARC Record fehlt! (CEO-Fraud möglich)",
                "safe": False,
                "details": f"_dmarc.{self.domain} hat keine TXT-Records"
            }
        except dns.exception.Timeout:
            return {
                "check": "DMARC Record",
                "message": f"DNS-Abfrage Timeout",
                "safe": False,
                "details": f"Server antwortet nicht innerhalb von {self.timeout}s"
            }
        except Exception as e:
            return {
                "check": "DMARC Record",
                "message": f"Fehler beim Abrufen des DMARC Records",
                "safe": False,
                "details": str(e)
            }
    
    def check_mx_records(self) -> Dict:
        """Prüft auf MX (Mail Exchange) Records."""
        try:
            answers = self.resolver.resolve(self.domain, 'MX', lifetime=self.timeout)
            
            if answers:
                mx_count = len(answers)
                mx_list = [str(mx.exchange).rstrip('.') for mx in answers[:3]]
                
                # Mindestens ein MX-Record ist gut, mehrere sind besser
                if mx_count >= 2:
                    return {
                        "check": "MX Records",
                        "message": f"Multiple MX Records gefunden (Redundanz vorhanden)",
                        "safe": True,
                        "details": f"{mx_count} Mail Server: {', '.join(mx_list[:2])}"
                    }
                else:
                    return {
                        "check": "MX Records",
                        "message": f"MX Record gefunden (aber nur ein Server - kein Failover)",
                        "safe": True,
                        "details": f"Primary Mail Server: {mx_list[0]}"
                    }
            else:
                return {
                    "check": "MX Records",
                    "message": "Keine MX Records gefunden! (Domain kann keine E-Mails empfangen)",
                    "safe": False,
                    "details": "Domain ist nicht als Mail-Server konfiguriert"
                }
        
        except dns.resolver.NXDOMAIN:
            return {
                "check": "MX Records",
                "message": "Domain existiert nicht im DNS",
                "safe": False,
                "details": "NXDOMAIN - ungültige Domain"
            }
        except dns.resolver.NoAnswer:
            return {
                "check": "MX Records",
                "message": "Keine MX Records gefunden",
                "safe": False,
                "details": "Domain ist nicht als Mail-Server konfiguriert"
            }
        except dns.exception.Timeout:
            return {
                "check": "MX Records",
                "message": f"DNS-Abfrage Timeout",
                "safe": False,
                "details": f"Server antwortet nicht innerhalb von {self.timeout}s"
            }
        except Exception as e:
            return {
                "check": "MX Records",
                "message": f"Fehler beim Abrufen der MX Records",
                "safe": False,
                "details": str(e)
            }
    
    def scan(self) -> List[Dict]:
        """Führt alle DNS-Sicherheitschecks durch."""
        print(f"\n{Fore.CYAN}--- DNS EMAIL SECURITY SCAN: {self.domain} ---{Style.RESET_ALL}")
        
        checks = [
            self.check_spf_record,
            self.check_dmarc_record,
            self.check_mx_records
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
