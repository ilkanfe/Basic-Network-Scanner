import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional
import jinja2
from weasyprint import HTML
from src.utils.logger import setup_logger
from src.utils.template_manager import TemplateManager
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self, output_dir: str = "reports", template_dir: str = "templates"):
        """
        Rapor oluşturucu sınıfı başlatıcısı.
        
        Args:
            output_dir (str): Raporların kaydedileceği dizin
            template_dir (str): Şablon dosyalarının bulunduğu dizin
        """
        self.logger = setup_logger(__name__)
        self.output_dir = output_dir
        self.template_dir = template_dir
        self.template_manager = TemplateManager(template_dir)
        
        # Jinja2 şablon ortamını başlat
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=True
        )
        
        # Çıktı dizinini oluştur
        os.makedirs(output_dir, exist_ok=True)
        
        # PDF stilleri
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='Turkish',
            fontName='Helvetica',
            fontSize=12,
            leading=14
        ))
        
    def _generate_filename(self, prefix: str, extension: str) -> str:
        """Benzersiz dosya adı oluşturur."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.output_dir, f"{prefix}_{timestamp}.{extension}")
        
    def save_json(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarını JSON formatında kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = self._generate_filename("scan", "json")
                
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=4, ensure_ascii=False)
                
            self.logger.info(f"JSON raporu kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"JSON raporu kaydedilemedi: {str(e)}")
            return ""
            
    def save_csv(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarını CSV formatında kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = self._generate_filename("scan", "csv")
                
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Başlıkları yaz
                writer.writerow(['IP', 'OS', 'OS Confidence', 'Port', 'State', 'Service', 'Version', 'Banner'])
                
                # Verileri yaz
                for host in scan_results.get('hosts', []):
                    ip = host.get('ip', '')
                    os_info = host.get('os_info', {})
                    os_name = os_info.get('name', 'Unknown')
                    os_conf = os_info.get('confidence', 0)
                    
                    for port, info in host.get('ports', {}).items():
                        service = info.get('service', {})
                        writer.writerow([
                            ip,
                            os_name,
                            os_conf,
                            port,
                            info.get('state', 'unknown'),
                            service.get('name', 'unknown'),
                            service.get('version', 'unknown'),
                            service.get('banner', '')
                        ])
                        
            self.logger.info(f"CSV raporu kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"CSV raporu kaydedilemedi: {str(e)}")
            return ""
            
    def save_summary(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarının özetini kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = self._generate_filename("summary", "txt")
                
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== Ağ Tarama Özeti ===\n\n")
                
                # Genel bilgiler
                f.write(f"Hedef: {scan_results.get('target', 'Bilinmiyor')}\n")
                f.write(f"Tarama Zamanı: {datetime.fromtimestamp(scan_results.get('scan_time', 0))}\n")
                f.write(f"Toplam Host: {scan_results.get('stats', {}).get('total_hosts', 0)}\n")
                f.write(f"Aktif Host: {scan_results.get('stats', {}).get('active_hosts', 0)}\n\n")
                
                # OS dağılımı
                f.write("=== İşletim Sistemi Dağılımı ===\n")
                for os_name, stats in scan_results.get('analysis', {}).get('os_distribution', {}).items():
                    f.write(f"{os_name}: {stats['count']} host (Güven: {stats['confidence_avg']:.2f})\n")
                f.write("\n")
                
                # Port istatistikleri
                f.write("=== Port İstatistikleri ===\n")
                for port, stats in scan_results.get('analysis', {}).get('port_analysis', {}).items():
                    f.write(f"Port {port}: {stats['open']} açık, {stats['closed']} kapalı\n")
                f.write("\n")
                
                # Güvenlik analizi
                f.write("=== Güvenlik Analizi ===\n")
                security = scan_results.get('analysis', {}).get('security_analysis', {})
                f.write(f"Toplam Sorun: {security.get('total_issues', 0)}\n")
                f.write(f"Etkilenen Host: {security.get('hosts_with_issues', 0)}\n")
                
            self.logger.info(f"Özet raporu kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Özet raporu kaydedilemedi: {str(e)}")
            return ""
            
    def save_pdf(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarını PDF formatında kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = self._generate_filename("scan", "pdf")
                
            # HTML şablonunu yükle
            template = self.template_env.get_template("report_template.html")
            
            # Şablonu doldur
            html_content = template.render(
                scan_results=scan_results,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # HTML'i PDF'e dönüştür
            HTML(string=html_content).write_pdf(filename)
            
            self.logger.info(f"PDF raporu kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"PDF raporu kaydedilemedi: {str(e)}")
            return ""
            
    def save_html(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarını HTML formatında kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = self._generate_filename("scan", "html")
                
            # HTML şablonunu yükle
            template = self.template_env.get_template("report_template.html")
            
            # Şablonu doldur
            html_content = template.render(
                scan_results=scan_results,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # HTML'i kaydet
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"HTML raporu kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"HTML raporu kaydedilemedi: {str(e)}")
            return ""

    def save_scan_results(self, scan_results: Dict, format: str = 'json', filename: Optional[str] = None) -> str:
        """
        Tarama sonuçlarını belirtilen formatta kaydeder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            format (str): Kaydetme formatı ('json', 'csv', 'html', 'pdf', 'summary')
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if format not in ['json', 'csv', 'html', 'pdf', 'summary']:
                raise ValueError(f"Desteklenmeyen format: {format}")
                
            if filename is None:
                filename = self._generate_filename("scan", format)
                
            if format == 'json':
                return self.save_json(scan_results, filename)
            elif format == 'csv':
                return self.save_csv(scan_results, filename)
            elif format == 'html':
                return self.save_html(scan_results, filename)
            elif format == 'pdf':
                return self.save_pdf(scan_results, filename)
            elif format == 'summary':
                return self.save_summary(scan_results, filename)
                
        except Exception as e:
            self.logger.error(f"Tarama sonuçları kaydedilemedi: {str(e)}")
            return "" 