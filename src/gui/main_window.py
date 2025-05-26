from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox
from PyQt5.QtCore import Qt
from src.scanner.port_scanner import PortScanner
from src.scanner.device_detector import DeviceDetector

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ağ Tarayıcı")
        self.setGeometry(100, 100, 800, 600)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Hedef IP girişi
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Hedef IP (örn. 192.168.1.0/24)")
        layout.addWidget(QLabel("Hedef IP:"))
        layout.addWidget(self.target_input)
        
        # Port aralığı girişi
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port Aralığı (örn. 1-1024)")
        layout.addWidget(QLabel("Port Aralığı:"))
        layout.addWidget(self.port_input)
        
        # Tarama tipi seçimi
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP", "SYN"])
        layout.addWidget(QLabel("Tarama Tipi:"))
        layout.addWidget(self.scan_type)
        
        # Servis tespiti seçeneği
        self.service_detection = QCheckBox("Servis Tespiti")
        layout.addWidget(self.service_detection)
        
        # Tarama başlat butonu
        self.scan_button = QPushButton("Taramayı Başlat")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Sonuçlar için metin alanı
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Sonuçlar:"))
        layout.addWidget(self.results_text)
        
        # Port tarayıcı ve cihaz tespitçi
        self.scanner = PortScanner()
        self.device_detector = DeviceDetector()
        
    def start_scan(self):
        target = self.target_input.text()
        port_range = self.port_input.text()
        scan_type = self.scan_type.currentText()
        service_detection = self.service_detection.isChecked()
        
        # Port aralığını parse et
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in port_range.split(",")]
        
        # Taramayı başlat
        results = self.scanner.scan(target, ports, scan_type, service_detection)
        
        # Sonuçları göster
        self.results_text.clear()
        
        # Açık portları göster
        if results['open_ports']:
            self.results_text.append("Açık Portlar:")
            for port in results['open_ports']:
                self.results_text.append(f"Port {port['port']}: open")
        
        # Servisleri göster
        if results['open_ports']:
            self.results_text.append("\nTespit Edilen Servisler:")
            for port in results['open_ports']:
                if port['service']:
                    self.results_text.append(f"Port {port['port']}: {port['service']}")
                    if 'banner' in port['service']:
                        self.results_text.append(f"  Banner: {port['service']['banner']}")
        
        # MAC adreslerini göster
        self.results_text.append("\nAğdaki Cihazlar (MAC Adresleri):")
        devices = self.device_detector.get_all_devices_from_arp()
        if not devices:
            self.results_text.append("Ağda cihaz bulunamadı veya ARP tablosu boş.")
        else:
            for d in devices:
                if d['ip'].startswith('192.168.1.'):
                    self.results_text.append(f"IP: {d['ip']}  MAC: {d['mac']}") 