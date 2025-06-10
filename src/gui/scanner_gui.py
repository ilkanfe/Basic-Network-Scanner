import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
import sys
import os
import asyncio
from typing import Dict, List, Optional
import json

# Ana dizini Python path'ine ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.visualization.report_generator import ReportGenerator
from src.utils.network_utils import get_mac_and_vendor
from src.scanner.os_fingerprinter import OSFingerprinter
from src.scanner.network_discovery import NetworkDiscovery

class NetworkScannerGUI:    
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("800x600")
        
        # Ana frame'i oluştur
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # GUI bileşenlerini oluştur
        self.create_widgets()
        
        # Tarayıcı nesnelerini oluştur
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.os_fingerprinter = OSFingerprinter()
        self.network_discovery = NetworkDiscovery()
        
        # Rapor oluşturucuyu başlat
        self.report_generator = ReportGenerator()
        
        # Pencere boyutlandırma ayarları
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        
    def create_widgets(self):
        """GUI bileşenlerini oluşturur"""
        # Üst panel (Kontroller)
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Tarama Kontrolleri", padding="10")
        self.control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)
        
        # IP adresi girişi
        ttk.Label(self.control_frame, text="Hedef IP:").grid(row=0, column=0, sticky=tk.W)
        self.target_ip = ttk.Entry(self.control_frame, width=30)
        self.target_ip.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.target_ip.insert(0, "192.168.1.1")  # Varsayılan IP
        
        # Port aralığı girişi
        ttk.Label(self.control_frame, text="Port Aralığı:").grid(row=1, column=0, sticky=tk.W)
        self.port_range = ttk.Entry(self.control_frame, width=30)
        self.port_range.grid(row=1, column=1, sticky=tk.W, padx=5)
        self.port_range.insert(0, "1-1024")  # Varsayılan port aralığı
        
        # Tarama tipi seçimi
        ttk.Label(self.control_frame, text="Tarama Tipi:").grid(row=2, column=0, sticky=tk.W)
        self.scan_type = ttk.Combobox(self.control_frame, values=["TCP", "UDP", "SYN"], width=27)
        self.scan_type.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.scan_type.set("TCP")  # Varsayılan tarama tipi
        
        # Servis tespiti seçeneği
        self.service_detect = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.control_frame, text="Servis Tespiti", variable=self.service_detect).grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        # Tarama başlat butonu
        self.scan_button = ttk.Button(self.control_frame, text="Taramayı Başlat", command=self.start_scan)
        self.scan_button.grid(row=5, column=0, columnspan=2, pady=10)
        
        # Ağ keşfi butonu
        self.discover_button = ttk.Button(self.control_frame, text="Ağdaki Cihazları Keşfet", command=self.start_discovery)
        self.discover_button.grid(row=6, column=0, columnspan=2, pady=5)
        
        # Port ve servis sonuçları
        self.port_text = scrolledtext.ScrolledText(self.main_frame, width=90, height=15)
        self.port_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10, columnspan=2)
        
        # Rapor oluştur butonu
        self.report_button = ttk.Button(self.main_frame, text="Rapor Oluştur", command=self.generate_report, state='disabled')
        self.report_button.grid(row=2, column=0, pady=5, columnspan=2)
        
        # Durum çubuğunu oluştur
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # İlerleme çubuğunu oluştur
        self.progress = ttk.Progressbar(self.root, length=300, mode='determinate')
        self.progress.grid(row=2, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Tarama sonuçları
        self.scan_results = None
        
    def update_status(self, message: str):
        """Durum çubuğunu günceller"""
        self.status_var.set(message)
        self.root.update_idletasks()
        
    def show_error(self, title: str, message: str):
        """Hata mesajını gösterir"""
        messagebox.showerror(title, message)
        self.update_status(f"Hata: {message}")
        
    def show_info(self, title: str, message: str):
        """Bilgi mesajını gösterir"""
        messagebox.showinfo(title, message)
        self.update_status(message)
        
    def start_scan(self):
        """Tarama işlemini başlatır"""
        try:
            # Giriş değerlerini al ve doğrula
            target = self.target_ip.get().strip()
            port_range = self.port_range.get().strip()
            scan_type = self.scan_type.get().lower()
            detect_services = self.service_detect.get()
            
            if not target:
                self.show_error("Hata", "Hedef IP adresi gerekli")
                return
                
            if not port_range:
                self.show_error("Hata", "Port aralığı gerekli")
                return
                
            # Port aralığını parse et
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                else:
                    start_port = end_port = int(port_range)
            except ValueError:
                self.show_error("Hata", "Geçersiz port aralığı formatı")
                return
                
            # Arayüzü devre dışı bırak
            self.scan_button.state(['!disabled'])
            self.port_text.delete(1.0, tk.END)
            self.progress['value'] = 0
            self.update_status("Tarama başlatılıyor...")
            
            # Taramayı ayrı bir thread'de başlat
            thread = threading.Thread(target=self.run_scan)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            self.show_error("Hata", f"Tarama başlatılamadı: {str(e)}")
            self.scan_button.state(['!disabled'])
            
    def run_scan(self):
        """Tarama işlemini yürütür"""
        try:
            # Giriş değerlerini al
            target = self.target_ip.get().strip()
            port_range = self.port_range.get().strip()
            scan_type = self.scan_type.get().lower()
            detect_services = self.service_detect.get()
            
            # Port aralığını parse et
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
                
            # Asenkron tarama işlemini başlat
            asyncio.run(self._run_scan_async(target, start_port, end_port, scan_type, detect_services))
            
        except Exception as e:
            self.show_error("Hata", f"Tarama sırasında hata oluştu: {str(e)}")
            self.scan_button.state(['!disabled'])
            self.progress['value'] = 0
            
    async def _run_scan_async(self, target: str, start_port: int, end_port: int, scan_type: str, detect_services: bool):
        """Asenkron tarama işlemini yürütür"""
        try:
            total_ports = end_port - start_port + 1
            scanned_ports = 0
            
            # Port taraması yap
            port_scanner = PortScanner()
            all_scanned_ports = {}
            
            # Portları gruplar halinde tara
            port_groups = [list(range(start_port + i, min(start_port + i + 50, end_port + 1))) 
                         for i in range(0, total_ports, 50)]
            
            for group in port_groups:
                group_results = await port_scanner.scan_ports(target, group[0], group[-1], scan_type)
                all_scanned_ports.update(group_results)
                
                scanned_ports += len(group)
                progress = (scanned_ports / total_ports) * 100
                self.progress['value'] = progress
                self.update_status(f"Tarama devam ediyor... {progress:.1f}%")
                
            # Açık portları bul
            open_ports = {port: state for port, state in all_scanned_ports.items() if state == "open"}
            
            # Servis tespiti yap
            services = {}
            if detect_services and open_ports:
                self.update_status("Servis tespiti yapılıyor...")
                service_detector = ServiceDetector()
                services = await service_detector.detect_services(target, open_ports)
                
            # OS fingerprinting yap
            self.update_status("İşletim sistemi tespiti yapılıyor...")
            os_info = await self.os_fingerprinter.detect_os(target)
            
            # Sonuçları göster
            self.show_results(all_scanned_ports, services, os_info, scan_type)
            self.update_status("Tarama tamamlandı")
            self.show_info("Bilgi", "Tarama başarıyla tamamlandı")
            
        except Exception as e:
            self.show_error("Hata", f"Tarama sırasında hata oluştu: {str(e)}")
            
        finally:
            self.scan_button.state(['!disabled'])
            self.progress['value'] = 0
            self.report_button.state(['!disabled'])
            
    def show_results(self, ports: Dict[int, str], services: Dict[int, Dict], os_info: Dict, scan_type: str):
        """Tarama sonuçlarını gösterir"""
        try:
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
            if os_info:
                result_text += "İşletim Sistemi Tespiti:\n"
                result_text += f"OS Adı: {os_info.get('name', 'Bilinmiyor')}\n"
                result_text += f"Güven Skoru: {os_info.get('confidence', 0):.2f}\n"
                result_text += f"TTL Analizi: {os_info.get('ttl_analysis', {}).get('os', 'Bilinmiyor')}\n"
                result_text += f"TCP Stack Analizi: {os_info.get('stack_analysis', {}).get('behavior', 'Bilinmiyor')}\n"
                result_text += "-" * 50 + "\n\n"
            
            # Port sonuçlarını göster
            result_text += f"Port Tarama Sonuçları ({scan_type.upper()}):\n"
            open_count = 0
            closed_count = 0
            
            # Portları sırala ve göster
            for port, state in sorted(ports.items()):
                if state == "open":
                    open_count += 1
                    service_info = services.get(port, {})
                    service_name = service_info.get('name', 'bilinmiyor')
                    service_version = service_info.get('version', 'bilinmiyor')
                    
                    result_text += f"Port {port}: AÇIK"
                    if service_name != 'bilinmiyor':
                        result_text += f" - {service_name}"
                        if service_version != 'bilinmiyor':
                            result_text += f" {service_version}"
                    result_text += "\n"
                elif state == "closed":
                    closed_count += 1
            
            result_text += f"\nTarama Tamamlandı!\n"
            result_text += f"Toplam Açık Port: {open_count}\n"
            result_text += f"Toplam Kapalı Port: {closed_count}\n"
            result_text += f"Toplam Taranan Port: {len(ports)}\n"
            
            self.port_text.insert(tk.END, result_text)
            
        except Exception as e:
            self.show_error("Hata", f"Sonuçlar gösterilirken hata oluştu: {str(e)}")
        
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

    def start_discovery(self):
        """Ağ keşfini başlatır"""
        self.update_status("Ağdaki cihazlar keşfediliyor...")
        self.progress['value'] = 0
        self.discover_button['state'] = 'disabled'
        self.scan_button['state'] = 'disabled'
        
        # Asenkron keşif işlemini başlat
        threading.Thread(target=self._run_discovery_async, daemon=True).start()
        
    def _run_discovery_async(self):
        """Asenkron ağ keşfi işlemini yürütür"""
        try:
            # Event loop oluştur
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Ağ keşfini başlat
            devices = loop.run_until_complete(self.network_discovery.discover_devices())
            
            # Sonuçları göster
            self.root.after(0, lambda: self.show_discovery_results(devices))
            
        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"Ağ keşfi sırasında hata: {str(e)}"))
        finally:
            loop.close()
            self.root.after(0, self._reset_buttons)
            
    def show_discovery_results(self, devices: List[Dict]):
        """Keşfedilen cihazları gösterir"""
        self.port_text.delete(1.0, tk.END)
        
        if not devices:
            self.port_text.insert(tk.END, "Hiçbir cihaz bulunamadı.\n")
            return
            
        self.port_text.insert(tk.END, f"Keşfedilen Cihazlar ({len(devices)}):\n")
        self.port_text.insert(tk.END, "=" * 50 + "\n\n")
        
        for device in devices:
            self.port_text.insert(tk.END, f"IP Adresi: {device['ip']}\n")
            if device['mac']:
                self.port_text.insert(tk.END, f"MAC Adresi: {device['mac']}\n")
            if device['vendor']:
                self.port_text.insert(tk.END, f"Üretici: {device['vendor']}\n")
            if device['hostname']:
                self.port_text.insert(tk.END, f"Hostname: {device['hostname']}\n")
            self.port_text.insert(tk.END, "-" * 30 + "\n\n")
            
        self.update_status("Ağ keşfi tamamlandı.")
        
    def _reset_buttons(self):
        """Butonları normal duruma getirir"""
        self.discover_button['state'] = 'normal'
        self.scan_button['state'] = 'normal'
        self.progress['value'] = 0

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 