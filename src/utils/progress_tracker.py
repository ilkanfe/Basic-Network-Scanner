from typing import Dict, Optional
import time
from datetime import datetime, timedelta
from src.utils.logger import setup_logger

class ProgressTracker:
    def __init__(self):
        """İlerleme takip sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        self.start_time = None
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.total_ports = 0
        self.scanned_ports = 0
        self.current_host = None
        self.current_port = None
        self.status = "Hazır"
        
    def start_scan(self, total_hosts: int, total_ports: int):
        """Tarama başlangıcını işaretler."""
        self.start_time = time.time()
        self.total_hosts = total_hosts
        self.total_ports = total_ports
        self.scanned_hosts = 0
        self.scanned_ports = 0
        self.status = "Tarama başladı"
        self.logger.info(f"Tarama başladı: {total_hosts} host, {total_ports} port")
        
    def update_host_progress(self, host: str, scanned_ports: int):
        """Host tarama ilerlemesini günceller."""
        self.current_host = host
        self.scanned_ports = scanned_ports
        self.scanned_hosts += 1
        
        # İlerleme yüzdesi
        host_progress = (self.scanned_hosts / self.total_hosts) * 100
        port_progress = (self.scanned_ports / self.total_ports) * 100
        
        # Kalan süre tahmini
        elapsed_time = time.time() - self.start_time
        if self.scanned_hosts > 0:
            time_per_host = elapsed_time / self.scanned_hosts
            remaining_hosts = self.total_hosts - self.scanned_hosts
            estimated_time = time_per_host * remaining_hosts
            eta = datetime.now() + timedelta(seconds=estimated_time)
        else:
            eta = "Hesaplanıyor..."
            
        self.status = f"Host: {host} ({self.scanned_hosts}/{self.total_hosts})"
        
        return {
            'host_progress': host_progress,
            'port_progress': port_progress,
            'scanned_hosts': self.scanned_hosts,
            'total_hosts': self.total_hosts,
            'scanned_ports': self.scanned_ports,
            'total_ports': self.total_ports,
            'current_host': host,
            'elapsed_time': self._format_time(elapsed_time),
            'estimated_time': self._format_time(estimated_time) if isinstance(estimated_time, (int, float)) else estimated_time,
            'eta': eta.strftime("%H:%M:%S") if isinstance(eta, datetime) else eta,
            'status': self.status
        }
        
    def update_port_progress(self, port: int):
        """Port tarama ilerlemesini günceller."""
        self.current_port = port
        self.scanned_ports += 1
        
        # İlerleme yüzdesi
        port_progress = (self.scanned_ports / self.total_ports) * 100
        
        # Kalan süre tahmini
        elapsed_time = time.time() - self.start_time
        if self.scanned_ports > 0:
            time_per_port = elapsed_time / self.scanned_ports
            remaining_ports = self.total_ports - self.scanned_ports
            estimated_time = time_per_port * remaining_ports
            eta = datetime.now() + timedelta(seconds=estimated_time)
        else:
            eta = "Hesaplanıyor..."
            
        self.status = f"Port: {port} ({self.scanned_ports}/{self.total_ports})"
        
        return {
            'port_progress': port_progress,
            'scanned_ports': self.scanned_ports,
            'total_ports': self.total_ports,
            'current_port': port,
            'elapsed_time': self._format_time(elapsed_time),
            'estimated_time': self._format_time(estimated_time) if isinstance(estimated_time, (int, float)) else estimated_time,
            'eta': eta.strftime("%H:%M:%S") if isinstance(eta, datetime) else eta,
            'status': self.status
        }
        
    def complete_scan(self):
        """Tarama tamamlandığını işaretler."""
        total_time = time.time() - self.start_time
        self.status = "Tarama tamamlandı"
        self.logger.info(f"Tarama tamamlandı: {self._format_time(total_time)}")
        
        return {
            'total_time': self._format_time(total_time),
            'scanned_hosts': self.scanned_hosts,
            'scanned_ports': self.scanned_ports,
            'status': self.status
        }
        
    def _format_time(self, seconds: float) -> str:
        """Süreyi formatlar."""
        return str(timedelta(seconds=int(seconds))) 