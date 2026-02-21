"""
E-Mail-Versand mit PDF-Anhang.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from dotenv import load_dotenv

# .env laden (lokal, wird nicht ins Repo gepusht)
load_dotenv()

# SMTP-Konfiguration (GMX)
SMTP_SERVER = os.getenv("SMTP_SERVER", "mail.gmx.net")
PORT = int(os.getenv("SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SMTP_SENDER", "")
PASSWORD = os.getenv("SMTP_PASSWORD", "")

# Standard-Empfänger (falls nichts übergeben wird)
DEFAULT_EMPFAENGER = "mt.sgschule@gmail.com"


def build_email_text(domain: str) -> str:
    """Erstellt den Standard-E-Mail-Text für den PDF-Report."""
    return (
        "Sehr geehrter Herr Mustermann,\n\n"
        f"anbei erhalten Sie den Security-Scan-Report für die Website {domain}. "
        "Bitte prüfen Sie die Ergebnisse und melden Sie sich bei Rückfragen gerne.\n\n"
        "Mit freundlichen Grüßen\n"
        "Security Scanner"
    )


def send_email_with_pdf(empfaenger, betreff, text, pdf_pfad, debug=False):
    """
    Sendet eine E-Mail mit PDF-Anhang.

    Args:
        empfaenger (str): Empfängeradresse
        betreff (str): Betreff der E-Mail
        text (str): Textinhalt der E-Mail
        pdf_pfad (str): Pfad zur PDF-Datei
    """
    if not SMTP_SERVER:
        print("SMTP_SERVER ist nicht gesetzt.")
        return False

    if not SENDER_EMAIL:
        print("SMTP_SENDER ist nicht gesetzt.")
        return False

    if not PASSWORD:
        print("SMTP_PASSWORD ist nicht gesetzt.")
        return False

    if not os.path.isfile(pdf_pfad):
        print(f"PDF-Datei nicht gefunden: {pdf_pfad}")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        if not empfaenger:
            empfaenger = DEFAULT_EMPFAENGER
        msg["To"] = empfaenger
        msg["Subject"] = betreff

        msg.attach(MIMEText(text, "plain"))

        with open(pdf_pfad, "rb") as pdf_file:
            attachment = MIMEApplication(pdf_file.read(), _subtype="pdf")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=os.path.basename(pdf_pfad),
            )
            msg.attach(attachment)

        server = smtplib.SMTP(SMTP_SERVER, PORT)
        if debug:
            server.set_debuglevel(1)
        server.starttls()
        server.login(SENDER_EMAIL, PASSWORD)
        server.sendmail(SENDER_EMAIL, empfaenger, msg.as_string())
        server.quit()
        print(f"E-Mail erfolgreich an {empfaenger} gesendet.")
        return True
    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")
        return False
