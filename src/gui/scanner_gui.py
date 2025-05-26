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

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Basic Network Scanner")
        self.root.geometry("600x800")  # Pencere boyutunu dikey olarak uzattım
        
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
        ttk.Label(self.control_frame, text="Tarama Tipi:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.scan_type = ttk.Combobox(self.control_frame, values=["SYN", "TCP"], width=27)
        self.scan_type.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        self.scan_type.set("SYN")
        
        # Servis tespiti
        self.service_detect = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.control_frame, text="Servis Tespiti", variable=self.service_detect).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Tarama butonu
        self.scan_button = ttk.Button(self.control_frame, text="Taramayı Başlat", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(self.main_frame, length=580, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Alt panel (Sonuçlar)
        self.result_frame = ttk.LabelFrame(self.main_frame, text="Tarama Sonuçları", padding="5")
        self.result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Port ve servis sonuçları
        self.port_text = scrolledtext.ScrolledText(self.result_frame, width=70, height=30)
        self.port_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
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
            ports = await port_scanner.scan_ports(target, start_port, end_port, scan_type)
            
            # Açık portları bul
            open_ports = {port: state for port, state in ports.items() if state == "open"}
            
            # Servis tespiti yap
            services = {}
            if detect_services and open_ports:
                service_detector = ServiceDetector()
                services = await service_detector.detect_services(target, open_ports)
            
            # Sonuçları göster
            self.show_results(open_ports, services)
            
        except Exception as e:
            self.logger.error(f"Tarama hatası: {str(e)}")
            messagebox.showerror("Hata", f"Tarama sırasında hata oluştu: {str(e)}")
            
        finally:
            self.scan_button.config(state='normal')
            self.progress.stop()
            
    def show_results(self, ports: Dict[int, str], services: Dict[int, Dict]):
        """Tarama sonuçlarını gösterir"""
        # Port ve servis sonuçlarını göster
        port_text = "Açık Portlar:\n"
        for port, state in ports.items():
            port_text += f"Port {port}: {state}\n"
            
        if services:
            port_text += "\nTespit Edilen Servisler:\n"
            for port, service_info in services.items():
                service_name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                
                if service_name != 'unknown':
                    if product and version and version != 'unknown':
                        port_text += f"Port {port}: {service_name} ({product} {version})\n"
                    elif product:
                        port_text += f"Port {port}: {service_name} ({product})\n"
                    else:
                        port_text += f"Port {port}: {service_name}\n"
                else:
                    port_text += f"Port {port}: Bilinmeyen servis\n"
                    
                if service_info.get('banner'):
                    port_text += f"  Banner: {service_info['banner']}\n"
        
        self.port_text.delete(1.0, tk.END)
        self.port_text.insert(tk.END, port_text)
    
    def finish_scan(self):
        self.progress.stop()
        self.scan_button.state(['!disabled'])
        self.report_button.state(['!disabled'])
    
    def generate_report(self):
        if not self.scan_results:
            messagebox.showwarning("Uyarı", "Önce tarama yapmalısınız!")
            return
        
        try:
            reporter = ReportGenerator()
            report_path = reporter.generate_report(self.scan_results)
            messagebox.showinfo("Başarılı", f"Rapor oluşturuldu: {report_path}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturulurken bir hata oluştu: {str(e)}")

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 