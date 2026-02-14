"""
PDF Report Generator
Erstellt professionelle Audit-Reports als PDF

Der "Consultant" - nimmt nackte Daten und macht sie für das Management lesbar
"""

import datetime
from pathlib import Path
from typing import List, Dict
from fpdf import FPDF
from colorama import Fore, Style


class PDFReportGenerator:
    """Generiert professionelle Sicherheits-Audit PDF-Reports"""
    
    def __init__(self, domain: str, company_name: str = "Security Scanner"):
        """
        Initialisiert den PDF-Generator
        
        Args:
            domain: Die gescannte Domain
            company_name: Name der Firma/Organisation für den Report Header
        """
        self.domain = domain
        self.company_name = company_name
        self.pdf = None
        self.results = []
        self.timestamp = datetime.datetime.now()
    
    def _create_pdf(self):
        """Erstellt ein neues PDF-Dokument mit Standard-Setup"""
        self.pdf = FPDF()
        self.pdf.add_page()
        self.pdf.set_auto_page_break(auto=True, margin=15)
    
    def _add_header(self):
        """Fügt Header mit Titel, Datum und Grundinfo hinzu"""
        # Titel
        self.pdf.set_font("helvetica", "B", 18)
        self.pdf.cell(0, 15, "Security Audit Report", ln=1, align="C")
        
        # Subtitel
        self.pdf.set_font("helvetica", "", 11)
        self.pdf.cell(0, 8, self.domain.upper(), ln=1, align="C")
        
        # Trennlinie
        self.pdf.set_draw_color(100, 100, 100)
        self.pdf.line(15, self.pdf.get_y(), 195, self.pdf.get_y())
        self.pdf.ln(8)
        
        # Metainformationen
        self.pdf.set_font("helvetica", "", 9)
        self.pdf.set_text_color(64, 64, 64)
        
        datum = self.timestamp.strftime("%d.%m.%Y %H:%M:%S")
        self.pdf.cell(0, 5, f"Generiert am: {datum}", ln=1)
        
        self.pdf.cell(0, 5, f"Scan-Domain: {self.domain}", ln=1)
        self.pdf.cell(0, 5, f"Scanner: {self.company_name}", ln=1)
        
        self.pdf.set_text_color(0, 0, 0)  # Zurück zu schwarz
        self.pdf.ln(5)
    
    def _add_summary(self, results: List[Dict]):
        """Fügt Zusammenfassungs-Box hinzu"""
        passed = sum(1 for r in results if r["safe"])
        failed = sum(1 for r in results if not r["safe"])
        total = len(results)
        success_rate = (passed / total * 100) if total > 0 else 0
        
        # Titel
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.cell(0, 6, "Sicherheits-Zusammenfassung", ln=1, border=0)
        
        # Box zeichnen
        y_start = self.pdf.get_y()
        self.pdf.set_draw_color(200, 200, 200)
        self.pdf.rect(15, y_start, 180, 20)
        
        # 3 Spalten mit 60er Breite
        col_width = 60
        x_start = 18
        y_pos = y_start + 3
        
        self.pdf.set_font("helvetica", "", 9)
        
        # Spalte 1: Bestanden (grün)
        self.pdf.set_xy(x_start, y_pos)
        self.pdf.set_text_color(0, 150, 0)
        self.pdf.cell(col_width, 6, f"Bestanden: {passed}/{total}", border=0, align="L")
        
        # Spalte 2: Fehlgeschlagen (rot)
        self.pdf.set_xy(x_start + col_width, y_pos)
        self.pdf.set_text_color(200, 0, 0)
        self.pdf.cell(col_width, 6, f"Fehlgeschlagen: {failed}/{total}", border=0, align="L")
        
        # Spalte 3: Erfolgsrate (schwarz)
        self.pdf.set_xy(x_start + 2 * col_width, y_pos)
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.cell(col_width, 6, f"Erfolgsrate: {success_rate:.1f}%", border=0, align="L")
        
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.set_y(y_start + 22)
        self.pdf.ln(5)
    
    def _add_results_table(self, results: List[Dict]):
        """Fügt die Ergebnisse als professionelle Tabelle hinzu"""
        # Tabellen-Titel
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.cell(0, 8, "Detaillierte Audit-Ergebnisse", ln=1)
        
        # Spaltenmasse
        col_widths = [50, 85, 25]
        
        # Tabellen-Header
        self.pdf.set_font("helvetica", "B", 10)
        self.pdf.set_draw_color(50, 50, 50)
        self.pdf.set_fill_color(220, 220, 220)
        
        self.pdf.cell(col_widths[0], 8, "Prüfung", border=1, fill=True)
        self.pdf.cell(col_widths[1], 8, "Beschreibung", border=1, fill=True)
        self.pdf.cell(col_widths[2], 8, "Status", border=1, fill=True, ln=1)
        
        # Tabellen-Inhalt
        self.pdf.set_font("helvetica", "", 8)
        self.pdf.set_draw_color(180, 180, 180)
        
        for i, result in enumerate(results):
            # Abwechselnde Zeilen-Farben
            if i % 2 == 0:
                self.pdf.set_fill_color(245, 245, 245)
            else:
                self.pdf.set_fill_color(255, 255, 255)
            
            # Check-Name (Column 1)
            self.pdf.cell(col_widths[0], 10, result["check"], border=1, fill=True)
            
            # Nachricht (Column 2) - mit Text-Trunkierung
            message = result["message"]
            if len(message) > 60:
                message = message[:57] + "..."
            self.pdf.cell(col_widths[1], 10, message, border=1, fill=True)
            
            # Status (Column 3) - mit Farben
            if result["safe"]:
                self.pdf.set_text_color(0, 150, 0)
                status_text = "PASS"
            else:
                self.pdf.set_text_color(200, 0, 0)
                status_text = "FAIL"
            
            self.pdf.cell(col_widths[2], 10, status_text, border=1, fill=True, ln=1, align="C")
            self.pdf.set_text_color(0, 0, 0)  # Zurück zu schwarz
    
    def _add_details_section(self, results: List[Dict]):
        """Fügt Detail-Informationen für fehlerhafte Checks hinzu"""
        failed_results = [r for r in results if not r["safe"]]
        
        if not failed_results:
            self.pdf.ln(5)
            self.pdf.set_font("helvetica", "B", 10)
            self.pdf.set_text_color(0, 150, 0)
            self.pdf.cell(0, 8, "Alle Sicherheitschecks bestanden!", ln=1)
            self.pdf.set_text_color(0, 0, 0)
            return
        
        # Fehlerhafte Checks Detail
        self.pdf.ln(8)
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.cell(0, 8, "Empfehlungen für fehlgeschlagene Checks", ln=1)
        
        self.pdf.set_font("helvetica", "", 9)
        
        for result in failed_results:
            # Überschrift des Fehlers
            self.pdf.set_text_color(200, 0, 0)
            self.pdf.set_font("helvetica", "B", 9)
            self.pdf.cell(0, 6, f"[FAIL] {result['check']}", ln=1)
            
            # Details
            self.pdf.set_text_color(0, 0, 0)
            self.pdf.set_font("helvetica", "", 8)
            self.pdf.cell(10, 5, "")  # Einrückung
            self.pdf.cell(170, 5, f"Problem: {result['message']}", ln=1)
            
            self.pdf.cell(10, 5, "")  # Einrückung
            details_text = result.get('details', 'Keine weiteren Details verfügbar')
            if len(details_text) > 100:
                details_text = details_text[:97] + "..."
            self.pdf.cell(170, 5, f"Details: {details_text}", ln=1)
            
            self.pdf.ln(2)
    
    def _add_footer(self):
        """Fügt einen professionellen Footer hinzu"""
        self.pdf.ln(10)
        
        # Trennlinie
        self.pdf.set_draw_color(100, 100, 100)
        self.pdf.line(15, self.pdf.get_y(), 195, self.pdf.get_y())
        
        # Footer-Text
        self.pdf.set_font("helvetica", "", 8)
        self.pdf.set_text_color(100, 100, 100)
        
        footer_text = f"{self.company_name} - Vertraulicher Sicherheitsbericht"
        self.pdf.cell(0, 5, footer_text, ln=1, align="C")
        
        self.pdf.cell(0, 5, "Warnung: Dieses Dokument enthält sensible Sicherheitsinformationen.", 
                 ln=1, align="C")
        
        self.pdf.set_text_color(0, 0, 0)
    
    def generate(self, results: List[Dict]) -> str:
        """
        Generiert einen kompletten PDF-Report
        
        Args:
            results: Liste von Audit-Ergebnissen
                     [{check: str, safe: bool, message: str, details: str}, ...]
        
        Returns:
            str: Pfad zur generierten PDF-Datei
        """
        self.results = results
        
        # PDF erstellen
        self._create_pdf()
        
        # Komponenten hinzufügen
        self._add_header()
        self._add_summary(results)
        self._add_results_table(results)
        self._add_details_section(results)
        self._add_footer()
        
        # Speichern
        project_root = Path(__file__).resolve().parents[1]
        audit_dir = project_root / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)

        filename = f"audit_report_{self.domain.replace('.', '_')}.pdf"
        file_path = audit_dir / filename
        self.pdf.output(str(file_path))
        
        return str(file_path)
    
    def generate_and_print(self, results: List[Dict]) -> str:
        """
        Generiert PDF und gibt Erfolgsmeldung aus
        
        Returns:
            str: Pfad zur generierten PDF-Datei
        """
        filename = self.generate(results)
        
        print(f"\n{Fore.GREEN}[OK] PDF erfolgreich generiert!{Style.RESET_ALL}")
        print(f"  Datei: {filename}")
        print(f"  Größe: {len(results)} Audit-Ergebnisse dokumentiert")
        
        return filename
