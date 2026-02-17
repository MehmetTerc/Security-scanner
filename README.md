# Security Scanner

Eine modulare Sicherheitsscanner-Anwendung zur Überprüfung von Website-Sicherheit.

## Projektstruktur

```
Security-scanner/
├── main.py                 # Orchestrator - delegiert an Module
├── config.py               # Konfigurationseinstellungen
├── modules/
│   ├── __init__.py         # Package-Definition
│   ├── web_scanner.py      # Website-Sicherheitschecks (5 Checks)
│   ├── dns_scanner.py      # E-Mail-Infrastruktur-Checks (3 Checks)
│   ├── ssl_scanner.py      # SSL-Zertifikat-Gueltigkeit (1 Check)
│   └── leakage_scanner.py  # Information-Leakage-Checks (2 Checks)
├── reports/
│   ├── __init__.py         # Package-Definition
│   └── pdf_generator.py    # Professioneller PDF-Report Generator
├── README.md               # Diese Datei
└── requirements.txt        # Dependencies
```

## Features

### 🌐 Web-Scanner (`modules/web_scanner.py`)

Der Web-Scanner prüft automatisch die folgenden Sicherheitsaspekte einer Website:

1. **HTTPS-Redirect**: Leitet HTTP automatisch auf HTTPS um?
2. **HSTS Header**: Ist der Strict-Transport-Security Header gesetzt?
3. **X-Frame-Options**: Verhindert Clickjacking-Angriffe?
4. **Content-Security-Policy**: Schützt vor XSS-Angriffen?
5. **Server-Leakage**: Verrät der Server-Header zu viele Informationen?

### 📧 DNS-Scanner (`modules/dns_scanner.py`)

Der DNS-Scanner prüft die E-Mail-Infrastruktur via öffentliche DNS-Records:

1. **SPF (Sender Policy Framework)**: Definiert, welche IP-Adressen im Namen der Domain E-Mails versenden dürfen
2. **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Sagt dem Empfänger, was er mit Mails tun soll, die SPF nicht bestehen
3. **MX Records**: Prüft auf Mail-Server-Konfiguration und Redundanz

### 🔒 SSL-Scanner (`modules/ssl_scanner.py`)

Der SSL-Scanner prüft die Gueltigkeit des TLS-Zertifikats:

1. **SSL Gueltigkeit**: Ermittelt verbleibende Tage bis zum Ablauf

### 🕵️ Leakage-Scanner (`modules/leakage_scanner.py`)

Der Leakage-Scanner prueft auf Informationslecks:

1. **Header Leakage**: Server- oder Framework-Header vorhanden
2. **security.txt**: Sicherheitshinweise unter /.well-known/security.txt

### 📋 Orchestrator (`main.py`)

Der Orchestrator ist der "Chef" und:
- Fragt den Benutzer nach der Domain
- Zeigt einen rechtlichen Warnhinweis mit Bestätigung
- Delegiert nacheinander an die Scanner-Module:
  - Web-Scanner (Website-Sicherheit)
  - DNS-Scanner (E-Mail-Infrastruktur)
   - SSL-Scanner (Zertifikats-Gueltigkeit)
   - Leakage-Scanner (Information-Leakage)
- Sammelt die Ergebnisse
- Generiert einen PDF-Report mit allen Findings

### 📊 Report Generator (`reports/pdf_generator.py`)

Der PDF-Report Generator ist der "Consultant":
- Nimmt strukturierte Daten vom Orchestrator
- Erstellt professionelle, farbcodierte PDF-Reports
- Zeigt Zusammenfassung (Erfolgsrate, PASS/FAIL Statistik)
- Tabellierte Audit-Ergebnisse (grün = bestanden, rot = fehlgeschlagen)
- Detaillierte Fehlerliste mit Empfehlungen
- Speichert als `audit_report_[domain].pdf`

**Features:**
- ✅ Professionelles Layout mit Header/Footer
- ✅ Farbcodierung (grün/rot) für Status
- ✅ Abwechselnde Zeilen-Farben für bessere Lesbarkeit
- ✅ Detaillierte Informationen für jede Prüfung
- ✅ Erfolgsrate und Statistik in Report integriert

## Installation

### Lokal (venv)

```bash
pip install -r requirements.txt
```

### Docker

```bash
docker build -t security-scanner .
docker run --rm -it security-scanner
```

## Verwendung

```bash
python main.py
```

Der Scanner wird dich dann auffordern:
1. Domain eingeben (z.B. `google.de`)
2. Rechtliche Bestätigung akzeptieren
3. Einen PDF-Report wird generiert

## Requirements

- Python 3.7+
- requests
- dnspython
- colorama
- fpdf

**Hinweis:** Die requirements.txt bleibt notwendig – sie wird sowohl für die lokale Installation als auch im Docker-Image verwendet.

## Beispiel-Output

```
==================================================
  🔒 SECURITY SCANNER - Orchestrator
==================================================

Welche Domain möchtest du scannen? (z.B. google.de): github.com

--- WEB SECURITY SCAN: github.com ---
[OK] HTTPS Redirect: HTTP wird auf HTTPS umgeleitet
[OK] HSTS Header: HSTS Header ist aktiviert
[OK] X-Frame-Options: X-Frame-Options Header ist aktiviert
[OK] Content-Security-Policy: CSP Header ist aktiviert
[OK] Server Header Leakage: Server Header vorhanden

--- DNS EMAIL SECURITY SCAN: github.com ---
[OK] SPF Record: SPF Record gefunden
[OK] DMARC Record: DMARC Record gefunden (reject-Policy)
[OK] MX Records: Multiple MX Records gefunden

--- SSL CERTIFICATE SCAN: github.com ---
[OK] SSL Gültigkeit: Noch 120 Tage

--- INFORMATION LEAKAGE SCAN: github.com ---
[WARNUNG] Header Leakage: Vorhandene Header: Server
[OK] security.txt: security.txt gefunden

=== ZUSAMMENFASSUNG ===
Bestanden: 10/11
Fehlgeschlagen: 1/11

[OK] PDF erfolgreich generiert!
   Datei: audit_report_github_com.pdf
   Größe: 11 Audit-Ergebnisse dokumentiert

✓ Scan abgeschlossen!
```

## Tests

```bash
python -m unittest
```

## PDF-Report Features

Der generierte PDF-Report enthält:

1. **Professioneller Header**
   - Domain-Name prominent dargestellt
   - Generierungs-Datum und -Zeit
   - Scanner-Informationen

2. **Sicherheits-Zusammenfassung** (highlighted Box)
   - Bestanden/Fehlgeschlagen Ratio
   - Erfolgsrate in Prozent

3. **Detaillierte Ergebnisse** (Tabelle)
   - Grüne Zeilen = Bestandene Checks
   - Rote Zeilen = Fehlgeschlagene Checks
   - Jeder Check mit Beschreibung und Status

4. **Fehler-Detaisl** (falls vorhanden)
   - Problem-Beschreibung
   - Technische Details
   - Anfälligkeit-Erklärung

5. **Vertraulicher Footer**
   - Warnung vor sensitiven Sicherheitsinformationen

## Sicherheitshinweise

⚠️ **Wichtig**: Dieser Scanner darf **nur** mit ausdrücklicher Genehmigung des Domain-Eigentümers verwendet werden. Unbefugtes Scanning von fremden Systemen ist illegal und strafbar!

## Lizenz

Nur mit Erlaubnis des Domain-Besitzers verwenden!
