import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
import sys
import os
import asyncio
from typing import Dict

# Ana dizini Python path'ine ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.visualization.report_generator import ReportGenerator
from src.utils.network_utils import get_mac_and_vendor
from src.scanner.os_fingerprinter import OSFingerprinter

class NetworkScannerGUI:    
    def __init__(self, root):
        self.root = root
        self.root.title("Basic Network Scanner")
        self.root.geometry("800x700")  # Pencere boyutunu büyüttüm
        
        # Ana frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Üst panel (Kontroller)
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Tarama Kontrolleri", padding="5")
        self.control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Kontroller için grid yapısı
        # Hedef IP girişi
        ttk.Label(self.control_frame, text="Hedef IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.target_ip = ttk.Entry(self.control_frame, width=30)
        self.target_ip.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        self.target_ip.insert(0, "192.168.1.1")
        
        # Port aralığı
        ttk.Label(self.control_frame, text="Port Aralığı:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.port_range = ttk.Entry(self.control_frame, width=30)
        self.port_range.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        self.port_range.insert(0, "1-1024")
        
        # Tarama tipi
        self.scan_type_label = ttk.Label(self.control_frame, text="Tarama Tipi:")
        self.scan_type_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.scan_type = ttk.Combobox(self.control_frame, values=["TCP", "UDP"], width=27)
        self.scan_type.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.scan_type.set("TCP")
        
        # Servis tespiti
        self.service_detect = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.control_frame, text="Servis Tespiti", variable=self.service_detect).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Tarama butonu
        self.scan_button = ttk.Button(self.control_frame, text="Taramayı Başlat", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(self.main_frame, length=780, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Alt panel (Sonuçlar)
        self.result_frame = ttk.LabelFrame(self.main_frame, text="Tarama Sonuçları", padding="5")
        self.result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Port ve servis sonuçları
        self.port_text = scrolledtext.ScrolledText(self.result_frame, width=90, height=15)
        self.port_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        # Rapor oluştur butonu
        self.report_button = ttk.Button(self.main_frame, text="Rapor Oluştur", command=self.generate_report, state='disabled')
        self.report_button.grid(row=3, column=0, pady=5)
        
        # Tarama sonuçları
        self.scan_results = None
        
        # Grid ağırlıklarını ayarla
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(2, weight=1)
        self.result_frame.columnconfigure(0, weight=1)
        self.result_frame.rowconfigure(0, weight=1)
        
        self.os_fingerprinter = OSFingerprinter()
        
    def start_scan(self):
        # Arayüzü devre dışı bırak
        self.scan_button.state(['disabled'])
        self.port_text.delete(1.0, tk.END)
        self.progress.start()
        
        # Taramayı ayrı bir thread'de başlat
        thread = threading.Thread(target=self.run_scan)
        thread.daemon = True
        thread.start()
    
    def run_scan(self):
        """Tarama işlemini başlatır"""
        try:
            # Giriş değerlerini al
            target = self.target_ip.get().strip()
            port_range = self.port_range.get().strip()
            scan_type = self.scan_type.get().lower()
            detect_services = self.service_detect.get()
            
            # Değerleri doğrula
            if not target:
                messagebox.showerror("Hata", "Hedef IP adresi gerekli")
                return
                
            if not port_range:
                messagebox.showerror("Hata", "Port aralığı gerekli")
                return
                
            # Port aralığını parse et
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                else:
                    start_port = end_port = int(port_range)
            except ValueError:
                messagebox.showerror("Hata", "Geçersiz port aralığı formatı")
                return
                
            # Tarama işlemini başlat
            self.scan_button.config(state='disabled')
            self.progress.start()
            
            # Asenkron tarama işlemini başlat
            asyncio.run(self._run_scan_async(target, start_port, end_port, scan_type, detect_services))
            
        except Exception as e:
            self.logger.error(f"Tarama başlatma hatası: {str(e)}")
            messagebox.showerror("Hata", f"Tarama başlatılamadı: {str(e)}")
            self.scan_button.config(state='normal')
            self.progress.stop()
            
    async def _run_scan_async(self, target: str, start_port: int, end_port: int, scan_type: str, detect_services: bool):
        """Asenkron tarama işlemini yürütür"""
        try:
            # Port taraması yap
            port_scanner = PortScanner()
            # Tüm taranmış portları al
            all_scanned_ports = await port_scanner.scan_ports(target, start_port, end_port, scan_type)
            
            # Açık portları bul (GUI'de göstermek için)
            open_ports = {port: state for port, state in all_scanned_ports.items() if state == "open"}
            
            # Servis tespiti yap
            services = {}
            if detect_services and open_ports:
                service_detector = ServiceDetector()
                services = await service_detector.detect_services(target, open_ports)
            
            # OS fingerprinting yap
            os_info = await self.os_fingerprinter.detect_os(target)
            
            # Sonuçları göster (tüm taranmış portları ilet)
            self.show_results(all_scanned_ports, services, os_info, scan_type)
            
        except Exception as e:
            self.logger.error(f"Tarama hatası: {str(e)}")
            messagebox.showerror("Hata", f"Tarama sırasında hata oluştu: {str(e)}")
            
        finally:
            self.scan_button.config(state='normal')
            self.progress.stop()
            
    def show_results(self, ports: Dict[int, str], services: Dict[int, Dict], os_info: Dict, scan_type: str):
        """Tarama sonuçlarını gösterir"""
        # Port ve servis sonuçlarını göster
        self.port_text.delete(1.0, tk.END)
        
        # Hedef bilgilerini göster
        target = self.target_ip.get().strip()
        mac, vendor = get_mac_and_vendor(target)
        
        result_text = f"Hedef: {target}\n"
        if mac:
            result_text += f"MAC Adresi: {mac}\n"
            result_text += f"Üretici: {vendor}\n"
        result_text += "-" * 50 + "\n\n"
        
        # OS fingerprinting sonuçlarını göster
        # Eğer os_info None ise boş bir sözlük olarak ayarla
        if os_info is None:
            os_info = {}

        result_text += "İşletim Sistemi Tespiti:\n"
        result_text += f"OS Adı: {os_info.get('name', 'Bilinmiyor')}\n"
        result_text += f"Güven Skoru: {os_info.get('confidence', 0):.2f}\n"
        result_text += f"TTL Analizi: {os_info.get('ttl_analysis', {}).get('os', 'Bilinmiyor')}\n"
        result_text += f"TCP Stack Analizi: {os_info.get('stack_analysis', {}).get('behavior', 'Bilinmiyor')}\n"
        result_text += "-" * 50 + "\n\n"
        
        # `ports` değişkeni artık `all_scanned_ports` içerir.
        # GUI'de gösterilecek açık portları buradan türetelim.
        open_ports_for_display = {port: state for port, state in ports.items() if state == "open"}
        closed_ports = {port: state for port, state in ports.items() if state == "closed"}
        filtered_ports = {port: state for port, state in ports.items() if state not in ["open", "closed"]}
        
        if open_ports_for_display:
            result_text += "Açık Portlar:\n"
            for port, state in open_ports_for_display.items():
                result_text += f"Port {port}: {state}\n"
            
            # Eğer services None ise veya boşsa kontrol et
            if services:
                result_text += "\nTespit Edilen Servisler:\n"
                for port, service_info in services.items():
                    service_name = service_info.get('name', 'unknown')
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    
                    if service_name != 'unknown':
                        if product and version and version != 'unknown':
                            result_text += f"Port {port}: {service_name} ({product} {version})\n"
                        elif product:
                            result_text += f"Port {port}: {service_name} ({product})\n"
                        else:
                            result_text += f"Port {port}: {service_name}\n"
                    else:
                        result_text += f"Port {port}: Bilinmeyen servis\n"
                        
                    if service_info.get('banner'):
                        result_text += f"  Banner: {service_info['banner']}\n"
        else:
            result_text += "Açık port bulunamadı.\n"
            
        self.port_text.insert(tk.END, result_text)
        self.report_button.config(state='normal')
        
        # scan_results'ı doğru tcp_ports ve udp_ports ile güncelle
        self.scan_results = {
            'target': target,
            'mac': mac,
            'vendor': vendor,
            'ports': ports, # Tüm taranmış portlar
            'services': services if services is not None else {}, # services boşsa boş sözlük ata
            'os_info': os_info if os_info is not None else {} # os_info boşsa boş sözlük ata
        }

        # scan_type'a göre tcp_ports ve udp_ports'u ayarla
        if scan_type == "tcp":
            self.scan_results['tcp_ports'] = ports
            self.scan_results['udp_ports'] = {}
        elif scan_type == "udp":
            self.scan_results['udp_ports'] = ports
            self.scan_results['tcp_ports'] = {}
        else:
            self.scan_results['tcp_ports'] = {}
            self.scan_results['udp_ports'] = {}
    
    def finish_scan(self):
        self.progress.stop()
        self.scan_button.state(['!disabled'])
        self.report_button.state(['!disabled'])
    
    def generate_report(self):
        if not self.scan_results:
            messagebox.showwarning("Uyarı", "Önce tarama yapmalısınız!")
            return
        
        try:
            print(f"Rapor oluşturulmadan önce scan_results: {self.scan_results}")
            reporter = ReportGenerator()
            report_path = reporter.generate_report(self.scan_results, self.scan_results['services'], self.scan_results['os_info'])
            messagebox.showinfo("Başarılı", f"Rapor oluşturuldu: {report_path}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturulurken bir hata oluştu: {str(e)}")

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 