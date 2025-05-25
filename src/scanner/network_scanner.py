import asyncio
import ipaddress
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import psutil
import time
from src.scanner.service_detector import ServiceDetector
from src.scanner.os_fingerprinter import OSFingerprinter
from src.visualization.scan_visualizer import ScanVisualizer
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error
from src.utils.report_generator import ReportGenerator
from src.utils.data_analyzer import DataAnalyzer

class NetworkScanner:
    def __init__(self, timeout: float = 2.0, max_workers: Optional[int] = None, output_dir: str = "reports",
                 max_retries: int = 3, retry_delay: float = 1.0):
        """
        Ağ tarayıcı sınıfı başlatıcısı.
        
        Args:
            timeout (float): Timeout süresi (saniye)
            max_workers (Optional[int]): Maksimum eşzamanlı tarama sayısı
            output_dir (str): Raporların kaydedileceği dizin
            max_retries (int): Maksimum yeniden deneme sayısı
            retry_delay (float): Yeniden denemeler arası bekleme süresi (saniye)
        """
        self.logger = setup_logger(__name__)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # CPU sayısına göre worker sayısını otomatik ayarla
        if max_workers is None:
            cpu_count = psutil.cpu_count(logical=False)
            self.max_workers = max(1, cpu_count * 2)  # Her CPU için 2 worker
        else:
            self.max_workers = max_workers
            
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self._scan_cache = {}
        
        # Alt modülleri başlat
        self.service_detector = ServiceDetector(timeout=timeout, max_workers=self.max_workers)
        self.os_fingerprinter = OSFingerprinter(timeout=timeout)
        self.visualizer = ScanVisualizer()
        self.report_generator = ReportGenerator(output_dir=output_dir)
        self.data_analyzer = DataAnalyzer()
        
    @lru_cache(maxsize=1000)
    def _get_cached_scan(self, host: str, ports: tuple) -> Optional[Dict]:
        """Önbellekten tarama sonucunu alır."""
        cache_key = f"{host}:{ports}"
        return self._scan_cache.get(cache_key)
        
    def _cache_scan(self, host: str, ports: tuple, scan_result: Dict):
        """Tarama sonucunu önbelleğe kaydeder."""
        cache_key = f"{host}:{ports}"
        self._scan_cache[cache_key] = scan_result
        
    async def _retry_with_backoff(self, func, *args, **kwargs):
        """
        Fonksiyonu yeniden deneme mekanizması ile çalıştırır.
        
        Args:
            func: Çalıştırılacak fonksiyon
            *args: Fonksiyon argümanları
            **kwargs: Fonksiyon anahtar kelime argümanları
            
        Returns:
            Fonksiyonun sonucu
        """
        last_error = None
        for attempt in range(self.max_retries):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    self.logger.warning(f"Deneme {attempt + 1}/{self.max_retries} başarısız. {wait_time} saniye bekleniyor...")
                    await asyncio.sleep(wait_time)
                    
        raise last_error
        
    async def _scan_host(self, host: str, ports: Set[int]) -> Optional[Dict]:
        """
        Tek bir host'u tarar.
        
        Args:
            host (str): Hedef IP
            ports (Set[int]): Taranacak portlar
            
        Returns:
            Optional[Dict]: Host tarama sonuçları
        """
        try:
            # Önbellekten kontrol et
            ports_tuple = tuple(sorted(ports))
            cached_result = self._get_cached_scan(host, ports_tuple)
            if cached_result:
                return cached_result
                
            # OS tespiti ve port taramasını paralel yap
            os_task = self._retry_with_backoff(self.os_fingerprinter.detect_os, host)
            port_task = self._retry_with_backoff(self.service_detector.detect_services, host, {p: 'unknown' for p in ports})
            
            os_info, port_results = await asyncio.gather(os_task, port_task)
            
            result = {
                'ip': host,
                'os_info': os_info,
                'ports': port_results
            }
            
            # Önbelleğe kaydet
            self._cache_scan(host, ports_tuple, result)
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Host taraması başarısız oldu ({host}): {str(e)}")
            return None
            
    async def scan_network(self, target: str, ports: Optional[Set[int]] = None, save_reports: bool = True) -> Dict:
        """
        Belirtilen hedefi veya ağı tarar.
        
        Args:
            target (str): Hedef IP veya CIDR notasyonunda ağ
            ports (Optional[Set[int]]): Taranacak portlar
            save_reports (bool): Raporları kaydet
            
        Returns:
            Dict: Tarama sonuçları
        """
        start_time = time.time()
        try:
            # Hedefi analiz et
            if '/' in target:
                # CIDR notasyonu
                network = ipaddress.ip_network(target)
                hosts = [str(ip) for ip in network.hosts()]
            else:
                # Tek IP
                hosts = [target]
                
            # Varsayılan portları ayarla
            if ports is None:
                ports = {21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080}
                
            # Hostları gruplara böl
            host_groups = [hosts[i:i + self.max_workers] for i in range(0, len(hosts), self.max_workers)]
            
            # Sonuçları topla
            results = []
            total_hosts = len(hosts)
            scanned_hosts = 0
            
            for group in host_groups:
                # Her grup için eşzamanlı tarama
                tasks = [self._scan_host(host, ports) for host in group]
                group_results = await asyncio.gather(*tasks)
                
                # Sonuçları filtrele ve ekle
                valid_results = [r for r in group_results if r]
                results.extend(valid_results)
                
                # İlerleme durumunu güncelle
                scanned_hosts += len(group)
                progress = (scanned_hosts / total_hosts) * 100
                self.logger.info(f"Tarama ilerlemesi: {progress:.1f}% ({scanned_hosts}/{total_hosts})")
                    
            # Sonuçları hazırla
            scan_results = {
                'scan_time': time.time() - start_time,
                'target': target,
                'hosts': results,
                'stats': {
                    'total_hosts': total_hosts,
                    'scanned_hosts': scanned_hosts,
                    'active_hosts': len(results),
                    'scan_duration': time.time() - start_time
                }
            }
            
            # Veri analizi yap
            analysis_results = self.data_analyzer.analyze_scan_results(scan_results)
            scan_results['analysis'] = analysis_results
            
            # Görselleştirme
            await self._visualize_results(results)
            
            # Raporları kaydet
            if save_reports:
                self.report_generator.save_json(scan_results)
                self.report_generator.save_csv(scan_results)
                self.report_generator.save_summary(scan_results)
                self.report_generator.save_pdf(scan_results)
            
            return scan_results
            
        except Exception as e:
            error_msg = f"Ağ taraması başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            return {
                'scan_time': time.time() - start_time,
                'target': target,
                'error': str(e),
                'hosts': [],
                'stats': {
                    'total_hosts': len(hosts) if 'hosts' in locals() else 0,
                    'scanned_hosts': scanned_hosts if 'scanned_hosts' in locals() else 0,
                    'active_hosts': 0,
                    'scan_duration': time.time() - start_time
                }
            }
            
    async def _visualize_results(self, results: List[Dict]) -> None:
        """
        Tarama sonuçlarını görselleştirir.
        
        Args:
            results (List[Dict]): Tarama sonuçları
        """
        try:
            # OS bilgilerini hazırla
            os_results = []
            for result in results:
                os_info = result.get('os_info', {})
                os_results.append({
                    'ip': result['ip'],
                    'name': os_info.get('name', 'Unknown'),
                    'confidence': os_info.get('confidence', 0)
                })
                
            # Görselleştirmeleri oluştur
            self.visualizer.create_os_distribution_pie(os_results, "reports/os_distribution.png")
            self.visualizer.create_port_heatmap(results, "reports/port_heatmap.html")
            self.visualizer.create_confidence_bar(os_results, "reports/confidence_bar.html")
            self.visualizer.create_interactive_dashboard(results, "reports/dashboard.html")
            
        except Exception as e:
            self.logger.error(f"Görselleştirme hatası: {str(e)}")
            
    def __del__(self):
        """ThreadPoolExecutor'ı temizle."""
        self.executor.shutdown(wait=False)
        # Önbelleği temizle
        self._scan_cache.clear() 