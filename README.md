# Security Scanner

Eine modulare Sicherheitsscanner-Anwendung zur Überprüfung von Website-Sicherheit.

## ⚖️ Wichtiger Hinweis zur Nutzung

**🔴 DIESES TOOL IST AUSSCHLIESSLICH FÜR FOLGENDE ZWECKE BESTIMMT:**
- ✅ **Authorisierte Sicherheits-Audits** (mit schriftlicher Genehmigung des Eigentümers)
- ✅ **Educational Purposes** (Lehr- und Lernzwecke in Sicherheitsschulungen)
- ✅ **Compliance & Pentesting** (zertifizierte Penetrationstester und Sicherheitsberater)
- ✅ **Eigenständige Domain-Überprüfung** (Überprüfung der eigenen Infrastruktur)

**❌ VERBOTEN Sind:**
- 🚫 Scans ohne explizite Genehmigung des Domain-Eigentümers
- 🚫 Unbefugtes Testen fremder Systeme (ist **STRAFBAR**)
- 🚫 Verwendung für böswillige Zwecke
- 🚫 Weitergabe an nicht-autorisierte Personen

**⚠️ Haftungsausschluss:** Der Autor/die Entwickler dieses Tools sind nicht verantwortlich für Missbrauch, illegale Aktivitäten oder Schäden, die durch die Nutzung dieses Tools entstehen. Die alleinige Verantwortung liegt bei der Person, die das Tool nutzt.

---

## Projektstruktur

```
Security-scanner/
├── main.py                 # Orchestrator - delegiert an Module
├── config.py               # Konfigurationseinstellungen
├── Dockerfile              # Docker Container Definition
├── LICENSE                 # MIT License + Authorized Use Policy
├── README.md               # Diese Datei (Dokumentation)
├── requirements.txt        # Python Dependencies
├── modules/
│   ├── __init__.py         # Package-Definition
│   ├── web_scanner.py      # Website-Sicherheitschecks (5 Checks)
│   ├── dns_scanner.py      # E-Mail-Infrastruktur-Checks (3 Checks)
│   ├── ssl_scanner.py      # SSL-Zertifikat-Gueltigkeit (1 Check)
│   ├── leakage_scanner.py  # Information-Leakage-Checks (2 Checks)
│   └── email_sender.py     # Versand des PDF-Reports per E-Mail
├── reports/
│   ├── __init__.py         # Package-Definition
│   └── pdf_generator.py    # Professioneller PDF-Report Generator
└── audit/
    └── audit_report_*.pdf  # Generierte Sicherheits-Reports
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
- Optionaler Versand des PDF-Reports per E-Mail

### 📊 Report Generator (`reports/pdf_generator.py`)

Der PDF-Report Generator ist der "Consultant":
- Nimmt strukturierte Daten vom Orchestrator
- Erstellt professionelle, mehrseiten PDF-Reports
- Speichert als `audit_report_[domain].pdf`

**Report-Struktur:**

**Seite 1: Management Summary**
- **Security Score** (prominentes Feld mit Prozentsatz)
  - ✅ Grün (GUT): > 80%
  - ⚠️ Gelb (MITTEL): >= 50%
  - ❌ Rot (KRITISCH): < 50%
- Status-Text basierend auf Score
- Übersicht der 4 geprüften Infrastruktur-Bereiche:
  - SSL/TLS (mit Kategorie-Score)
  - Web-Security (mit Kategorie-Score)
  - DNS-Konfiguration (mit Kategorie-Score)
  - Informationslecks (mit Kategorie-Score)
- Kontaktinformationen für Beratung

**Seite 2+: Detaillierte Audit-Ergebnisse**
- **Sicherheits-Zusammenfassung**: Bestanden / Fehlgeschlagen / Erfolgsrate (%)
- **Audit-Ergebnisse Tabelle**: 
  - Prüfung, Beschreibung, Status (PASS/FAIL)
  - Farbcodierung (grün = bestanden, rot = fehlgeschlagen)
  - Abwechselnde Zeilen-Farben für bessere Lesbarkeit
- **Empfehlungen für Fehlschläge**: Detaillierte Beschreibung & Lösungsvorschläge
- **Footer**: Vertraulichkeitshinweis und Scanner-Information

**Features:**
- ✅ Multi-Seiten Report mit Management Summary & Details
- ✅ Dynamischer Security Score mit Farbcodierung
- ✅ Kategorie-basierte Bewertung von Infrastruktur-Bereichen
- ✅ Erfolgsrate und Statistiken
- ✅ Professionelles Layout mit Header/Footer
- ✅ Farbige Kategorisierung aller Prüfungen

## Installation

### Lokal (venv)

```bash
pip install -r requirements.txt
```

### Docker

**Image bauen:**
```bash
docker build -t security-scanner .
```

**Container starten - Optionen (in dieser Reihenfolge):**

**Option 1: Mit Kommandozeilenargument (empfohlen für Automation):**
```bash
docker run -v ./audit:/app/audit security-scanner google.de
```
- Vollautomatisch, kein Input erforderlich
- Domain wird direkt übergeben
- Perfekt für Skripte und Cron-Jobs

**Option 2: Mit Umgebungsvariable:**
```bash
docker run -e DOMAIN=google.de -v ./audit:/app/audit security-scanner
```
- Auch automatisch
- Flexibel für Konfiguration

**Option 3: Interaktiv (Domain wird abgefragt):**
```bash
docker run -it -v ./audit:/app/audit security-scanner
```
- Der Container fragt nach Domain und Bestätigung
- Braucht `-it` Flags für interaktiven Input

### Wichtig: Image nach Code-Änderungen neu bauen
Wenn du den Code änderst, musst du das Docker Image neu bauen, damit die Änderungen wirksam werden:
```bash
docker build -t security-scanner .
```
Das `COPY . .` in der Dockerfile kopiert den Code nur **zum Build-Zeitpunkt**, nicht dynamisch!

## Verwendung

### Lokal
```bash
python main.py
```

### Docker
```bash
docker run -v ./audit:/app/audit -it security-scanner
```

Der Scanner wird dich dann auffordern:
1. Domain eingeben (z.B. `google.de`)
2. Rechtliche Bestätigung akzeptieren
3. Ein PDF-Report wird generiert und im `audit/` Ordner gespeichert als `audit_report_[domain].pdf`
4. Optional: PDF-Report per E-Mail senden

## E-Mail-Versand (SMTP)

Der E-Mail-Versand liest die Zugangsdaten aus einer lokalen .env-Datei (wird nicht ins Repo gepusht).

Beispiel [.env](.env):
- SMTP_SERVER=mail.gmx.net
- SMTP_PORT=587
- SMTP_SENDER=deine@gmx.de
- SMTP_PASSWORD=deinpasswort

## Requirements

- Python 3.7+
- requests
- dnspython
- colorama
- fpdf
- python-dotenv

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

## 📜 Lizenz

Dieses Projekt ist unter der **MIT License** lizenziert. Siehe [LICENSE](LICENSE) für Details.

**Wichtig:** Die Lizenz beinhaltet ein zusätzliches **Authorized Use Only Addendum**, das explizit erklärt, dass dieses Tool nur für folgende Zwecke verwendet werden darf:
- ✅ Autoritative Sicherheitsaudits (mit Genehmigung)
- ✅ Educational & Learning Purposes
- ✅ Compliance Testing
- ✅ Authorized Penetration Testing

## ⚖️ Rechtliche Warnung & Haftungsausschluss

**🔴 AUTHORIZED USE ONLY**

Dieser Security Scanner ist ein **passives Audit-Tool** für inspirierende und autorisierte Sicherheitstests. Die Nutzung unterliegt strengen rechtlichen Anforderungen:

### Erlaubte Verwendung:
- ✅ Tests **YOUR OWN DOMAIN** (der Eigentümer oder Autorisierter)
- ✅ **Mit expliziter schriftlicher Genehmigung** des Domain-Eigentümers
- ✅ **Educational purposes** in zertifizierten Sicherheitsschulungen
- ✅ **Professional Penetration Testing** durch zertifizierte Sicherheitsexperten
- ✅ **Compliance Audits** in autorisierten Rollen

### Verbotene Verwendung:
- 🚫 Scans **ohne Genehmigung** des Eigentümers → **ILLEGAL**
- 🚫 Unbefugtes Testen fremder Systeme → **STRAFBAR**
- 🚫 Verwendung für böswillige oder kriminelle Zwecke
- 🚫 Weitergabe an unbefugte Personen

### Haftungsausschluss:
Die Autoren und Beiträger dieses Tools sind **NICHT verantwortlich** für:
- Missbrauch oder illegale Nutzung
- Strafverfolgung aufgrund von unbefugtem Zugriff
- Schäden an Systemen oder Netzwerken
- Datenverlust oder andere Folgen der Verwendung

**Die gesamte Verantwortung liegt bei der Person, die das Tool nutzt.**

---

⚠️ **WICHTIG**: Unbefugtes Scanning fremder Systeme verstößt gegen Gesetze in den meisten Ländern (z.B. CFAA in den USA, StGB §303b in Deutschland) und kann zu strafrechtlicher Verfolgung führen!

---

## Lizenz

Nur mit Erlaubnis des Domain-Besitzers verwenden!
