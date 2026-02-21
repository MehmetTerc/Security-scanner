"""
Security Scanner - Orchestrator
Der "Chef" orchestriert die verschiedenen Scanner-Module

Scanner-Module:
- web_scanner.py: Überprüft Website-Sicherheit (HTTPS, Headers, etc.)
- dns_scanner.py: Überprüft E-Mail-Infrastruktur (SPF, DMARC, MX-Records)

Report-Generator:
- reports/pdf_generator.py: Erstellt professionelle Audit-Reports

Version: 1.0
"""

import sys
import os
from colorama import init, Fore, Style

# Module importieren
from modules.web_scanner import WebScanner
from modules.dns_scanner import DNSScanner
from modules.ssl_scanner import scan_ssl
from modules.leakage_scanner import scan_leakage
from modules.email_sender import send_email_with_pdf, build_email_text
from reports.pdf_generator import PDFReportGenerator

# Farben aktivieren
init(autoreset=True)

# Hier speichern wir die Ergebnisse aller Module für das PDF
audit_results = []


def display_welcome():
    """Zeigt eine Willkommensmeldung an."""
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"  🔒 SECURITY SCANNER - Orchestrator")
    print(f"{'='*50}{Style.RESET_ALL}\n")


def ask_for_domain() -> str:
    """
    Fragt den User nach der zu scannenden Domain.
    Priorität:
    1. Kommandozeilenargument: python main.py google.de
    2. Umgebungsvariable: DOMAIN=google.de python main.py
    3. User-Input (interaktiv)
    """
    # Versuch 1: Kommandozeilenargument
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
        print(f"{Fore.GREEN}Domain aus Argument: {domain}{Style.RESET_ALL}")
        return domain
    
    # Versuch 2: Umgebungsvariable
    domain_env = os.environ.get('DOMAIN', '').strip()
    if domain_env:
        print(f"{Fore.GREEN}Domain aus Umgebungsvariable: {domain_env}{Style.RESET_ALL}")
        return domain_env
    
    # Versuch 3: Interaktiv fragen (falls möglich)
    if not sys.stdin.isatty():
        print(f"{Fore.RED}Fehler: Keine Domain gefunden!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Optionen:{Style.RESET_ALL}")
        print(f"  1. Kommandozeilenargument: docker run security-scanner google.de")
        print(f"  2. Umgebungsvariable: docker run -e DOMAIN=google.de security-scanner")
        print(f"  3. Interaktiv: docker run -it security-scanner")
        sys.exit(1)
    
    domain = input(f"Welche Domain möchtest du scannen? (z.B. google.de): ").strip()
    
    if not domain:
        print(f"{Fore.RED}Domain darf nicht leer sein!{Style.RESET_ALL}")
        sys.exit(1)
    return domain


def display_legal_warning(domain: str) -> bool:
    """
    Zeigt einen rechtlichen Warnhinweis an und fragt nach Bestätigung.
    Returns: True wenn User zustimmt, False sonst.
    """
    # Im non-interaktiven Modus automatisch akzeptieren
    # (wenn gesagt wurde mit Kommandozeilenargument oder Umgebungsvariable)
    non_interactive = len(sys.argv) > 1 or os.environ.get('DOMAIN')
    
    if non_interactive or not sys.stdin.isatty():
        print(f"{Fore.YELLOW}[Non-interaktiver Modus] Rechtliche Bestätigung angenommen{Style.RESET_ALL}")
        return True
    
    print(f"\n{Fore.YELLOW}{'='*50}")
    print(f"  ⚠️  RECHTLICHER HINWEIS")
    print(f"{'='*50}{Style.RESET_ALL}")
    print(f"""
Du stimmst zu, dass:
  • Du die Berechtigung hast, {Fore.YELLOW}{domain}{Style.RESET_ALL} zu testen
  • Dieser Scan nur zu Sicherheitszwecken erfolgt
  • Du der Eigentümer oder autorisiert bist
  • Unbefugtes Testen ist ILLEGAL und strafbar

{Fore.RED}Missbrauch kann zu Strafverfolgung führen!{Style.RESET_ALL}
""")
    
    bestaetigung = input(f"Verstanden und Erlaubnis vorhanden? (ja/nein): ").strip().lower()
    return bestaetigung == 'ja'


def run_web_scanner(domain: str):
    """Führt den Web-Scanner aus und speichert Ergebnisse."""
    scanner = WebScanner(domain)
    results = scanner.scan()
    
    # Speichere Ergebnisse global
    global audit_results
    audit_results.extend(results)


def run_dns_scanner(domain: str):
    """Führt den DNS-Scanner aus und speichert Ergebnisse."""
    scanner = DNSScanner(domain)
    results = scanner.scan()
    
    # Speichere Ergebnisse global
    global audit_results
    audit_results.extend(results)


def run_ssl_scanner(domain: str):
    """Führt den SSL-Scanner aus und speichert Ergebnisse."""
    results = scan_ssl(domain)

    print(f"\n{Fore.CYAN}--- SSL CERTIFICATE SCAN: {domain} ---{Style.RESET_ALL}")
    for result in results:
        if result["safe"]:
            status = f"[{Fore.GREEN}OK{Style.RESET_ALL}]"
        else:
            status = f"[{Fore.RED}WARNUNG{Style.RESET_ALL}]"
        print(f"{status} {result['check']}: {result['message']}")

    # Speichere Ergebnisse global
    global audit_results
    audit_results.extend(results)


def run_leakage_scanner(domain: str):
    """Führt den Leakage-Scanner aus und speichert Ergebnisse."""
    results = scan_leakage(domain)

    print(f"\n{Fore.CYAN}--- INFORMATION LEAKAGE SCAN: {domain} ---{Style.RESET_ALL}")
    for result in results:
        if result["safe"]:
            status = f"[{Fore.GREEN}OK{Style.RESET_ALL}]"
        else:
            status = f"[{Fore.RED}WARNUNG{Style.RESET_ALL}]"
        print(f"{status} {result['check']}: {result['message']}")

    # Speichere Ergebnisse global
    global audit_results
    audit_results.extend(results)


def generate_pdf_report(domain: str):
    """Generiert einen PDF-Report mittels Report-Generator."""
    print(f"\n{Fore.CYAN}Erstelle PDF-Report...{Style.RESET_ALL}")
    
    try:
        # Verwende den PDFReportGenerator
        generator = PDFReportGenerator(domain, company_name="Security Scanner")
        filename = generator.generate_and_print(audit_results)
        return filename
    except Exception as e:
        print(f"{Fore.RED}Fehler bei PDF-Generierung: {str(e)}{Style.RESET_ALL}")
        raise



def display_summary():
    """Zeigt eine Zusammenfassung der Scan-Ergebnisse."""
    if not audit_results:
        return
    
    print(f"\n{Fore.CYAN}--- SCAN-ZUSAMMENFASSUNG ---{Style.RESET_ALL}")
    passed = sum(1 for r in audit_results if r["safe"])
    failed = sum(1 for r in audit_results if not r["safe"])
    total = len(audit_results)
    
    print(f"{Fore.GREEN}✓ Bestanden: {passed}/{total}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Fehlgeschlagen: {failed}/{total}{Style.RESET_ALL}")
    
    if failed > 0:
        print(f"\n{Fore.YELLOW}Fehlerhafte Checks:{Style.RESET_ALL}")
        for result in audit_results:
            if not result["safe"]:
                print(f"  • {result['check']}: {result['message']}")


def main():
    """Hauptfunktion - der Orchestrator."""
    display_welcome()
    
    # Schritt 1: Domain abfragen
    domain = ask_for_domain()
    
    # Schritt 2: Rechtlichen Hinweis zeigen und Bestätigung einholen
    if not display_legal_warning(domain):
        print(f"{Fore.RED}Scan abgebrochen. Du musst die Bedingungen akzeptieren.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Schritt 3: Module aufrufen (Delegation)
    print(f"\n{Fore.CYAN}Starte Scan-Module...{Style.RESET_ALL}")
    
    # Web-Scanner aufrufen
    try:
        run_web_scanner(domain)
    except Exception as e:
        print(f"{Fore.RED}Fehler bei Web-Scanner: {str(e)}{Style.RESET_ALL}")
    
    # DNS-Scanner aufrufen
    try:
        run_dns_scanner(domain)
    except Exception as e:
        print(f"{Fore.RED}Fehler bei DNS-Scanner: {str(e)}{Style.RESET_ALL}")

    # SSL-Scanner aufrufen
    try:
        run_ssl_scanner(domain)
    except Exception as e:
        print(f"{Fore.RED}Fehler bei SSL-Scanner: {str(e)}{Style.RESET_ALL}")

    # Leakage-Scanner aufrufen
    try:
        run_leakage_scanner(domain)
    except Exception as e:
        print(f"{Fore.RED}Fehler bei Leakage-Scanner: {str(e)}{Style.RESET_ALL}")
    
    # Schritt 4: Zusammenfassung anzeigen
    display_summary()
    
    # Schritt 5: PDF-Report generieren
    pdf_path = None
    try:
        pdf_path = generate_pdf_report(domain)
    except Exception as e:
        print(f"{Fore.RED}Fehler beim PDF-Export: {str(e)}{Style.RESET_ALL}")

    if pdf_path:
        # E-Mail-Versand nur im echten interaktiven Modus
        if sys.stdin.isatty() and len(sys.argv) <= 1 and not os.environ.get('DOMAIN'):
            send_choice = input("PDF per E-Mail senden? (ja/nein): ").strip().lower()
            if send_choice == "ja":
                empfaenger = input("Empfänger-E-Mail: ").strip()
                if empfaenger:
                    betreff = f"Security Scan Report für {domain}"
                    text = build_email_text(domain)
                    send_email_with_pdf(empfaenger, betreff, text, pdf_path)
                else:
                    print(f"{Fore.YELLOW}Keine Empfängeradresse angegeben.{Style.RESET_ALL}")
        else:
            if len(sys.argv) > 1 or os.environ.get('DOMAIN'):
                print(f"{Fore.YELLOW}E-Mail-Versand übersprungen (Non-interaktiver Modus){Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}✓ Scan abgeschlossen!{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan durch Benutzer unterbrochen.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Unerwarteter Fehler: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)