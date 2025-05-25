import nmap
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Set, List
from functools import lru_cache
import psutil
import time
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error
from src.utils.platform_utils import is_windows, get_platform_specific_command

class ServiceDetector:
    def __init__(self, timeout: float = 2.0, max_workers: Optional[int] = None,
                 max_retries: int = 3, retry_delay: float = 1.0):
        """
        Servis tespit sınıfı başlatıcısı.
        
        Args:
            timeout (float): Servis tespiti timeout süresi (saniye)
            max_workers (Optional[int]): Maksimum eşzamanlı tespit sayısı
            max_retries (int): Maksimum yeniden deneme sayısı
            retry_delay (float): Yeniden denemeler arası bekleme süresi (saniye)
        """
        self.logger = setup_logger(__name__)
        self.nm = nmap.PortScanner()
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
        self._service_cache = {}
        
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
        
    @lru_cache(maxsize=1000)
    def _get_cached_service(self, target_ip: str, port: int, protocol: str) -> Optional[Dict]:
        """Önbellekten servis bilgisini alır."""
        cache_key = f"{target_ip}:{port}:{protocol}"
        return self._service_cache.get(cache_key)
        
    def _cache_service(self, target_ip: str, port: int, protocol: str, service_info: Dict):
        """Servis bilgisini önbelleğe kaydeder."""
        cache_key = f"{target_ip}:{port}:{protocol}"
        self._service_cache[cache_key] = service_info
        
    async def detect_service(self, target_ip: str, port: int, protocol: str = 'tcp') -> Dict:
        """
        Belirtilen port üzerindeki servisi tespit eder.
        
        Args:
            target_ip (str): Hedef IP adresi
            port (int): Port numarası
            protocol (str): Protokol ('tcp' veya 'udp')
            
        Returns:
            Dict: Servis bilgileri
        """
        # Önbellekten kontrol et
        cached_service = self._get_cached_service(target_ip, port, protocol)
        if cached_service:
            return cached_service
            
        try:
            # Nmap ile servis tespiti ve banner grabbing'i paralel yap
            nmap_task = self._retry_with_backoff(self._nmap_scan, target_ip, [port])
            banner_task = self._retry_with_backoff(self._banner_grab, target_ip, port, protocol)
            
            nmap_result, banner = await asyncio.gather(nmap_task, banner_task)
            
            service_info = {
                'name': nmap_result.get('name', 'unknown'),
                'product': nmap_result.get('product', 'unknown'),
                'version': nmap_result.get('version', 'unknown'),
                'state': nmap_result.get('state', 'unknown'),
                'banner': banner,
                'detection_time': time.time()
            }
            
            # Önbelleğe kaydet
            self._cache_service(target_ip, port, protocol, service_info)
            
            return service_info
            
        except Exception as e:
            error_msg = f"Servis tespiti başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            return {
                'name': 'unknown',
                'product': 'unknown',
                'version': 'unknown',
                'state': 'unknown',
                'banner': None,
                'detection_time': time.time()
            }
            
    async def _nmap_scan(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Nmap ile servis tespiti yapar"""
        try:
            # Port listesini string'e çevir
            port_str = ','.join(map(str, ports))
            
            # Daha agresif Nmap taraması
            cmd = [
                'nmap',
                '-v',  # Verbose output
                '-sV',  # Versiyon tespiti
                '-sC',  # Varsayılan scriptleri çalıştır
                '-O',   # İşletim sistemi tespiti
                '--version-intensity', '9',  # Maksimum versiyon tespiti
                '--version-all',  # Tüm versiyon tespiti yöntemlerini dene
                '-A',  # Agresif tarama
                '-T4',  # Hızlı tarama
                '-p', port_str,
                target
            ]
            
            # Debug: Komutu göster
            self.logger.info(f"Çalıştırılan Nmap komutu: {' '.join(cmd)}")
            
            # Komutu çalıştır
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Debug: Nmap çıktısını göster
            output = stdout.decode('latin-1')
            self.logger.info(f"Nmap çıktısı:\n{output}")
            
            if process.returncode != 0:
                self.logger.warning(f"Nmap servis tespiti hatası: {stderr.decode('latin-1')}")
                return {}
            
            # Nmap çıktısını parse et
            results = {}
            current_port = None
            
            # Port ve servis bilgilerini bul
            for line in output.split('\n'):
                # Debug: Her satırı göster
                self.logger.debug(f"İşlenen satır: {line}")
                
                # Port numarasını bul
                if 'Discovered open port' in line:
                    try:
                        port = int(line.split('port')[1].split('/')[0].strip())
                        current_port = port
                        results[port] = {
                            'name': 'unknown',
                            'product': 'unknown',
                            'version': 'unknown',
                            'state': 'open',
                            'banner': None
                        }
                        self.logger.info(f"Port bulundu: {port}")
                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Port parse hatası: {str(e)}")
                        continue
                
                # Servis bilgilerini bul
                if current_port and 'Service Info:' in line:
                    info = line.split('Service Info:')[1].strip()
                    if ';' in info:
                        service, version = info.split(';', 1)
                        results[current_port]['name'] = service.strip()
                        results[current_port]['version'] = version.strip()
                        self.logger.info(f"Servis bilgisi bulundu: {service.strip()} - {version.strip()}")
                    else:
                        results[current_port]['name'] = info.strip()
                        self.logger.info(f"Servis bilgisi bulundu: {info.strip()}")
                
                # Banner bilgisini bul
                if current_port and 'Banner:' in line:
                    banner = line.split('Banner:')[1].strip()
                    results[current_port]['banner'] = banner
                    self.logger.info(f"Banner bulundu: {banner}")
            
            # Varsayılan port bilgilerini ekle
            for port in ports:
                if port not in results:
                    results[port] = {
                        'name': 'unknown',
                        'product': 'unknown',
                        'version': 'unknown',
                        'state': 'unknown',
                        'banner': None
                    }
                
                # Bilinen portlar için varsayılan bilgileri ekle
                if results[port]['name'] == 'unknown':
                    if port == 53:
                        results[port]['name'] = 'domain'
                        results[port]['product'] = 'DNS'
                    elif port == 80:
                        results[port]['name'] = 'http'
                        results[port]['product'] = 'HTTP'
                    elif port == 443:
                        results[port]['name'] = 'https'
                        results[port]['product'] = 'HTTPS'
                    elif port == 22:
                        results[port]['name'] = 'ssh'
                        results[port]['product'] = 'SSH'
                    elif port == 21:
                        results[port]['name'] = 'ftp'
                        results[port]['product'] = 'FTP'
                    elif port == 25:
                        results[port]['name'] = 'smtp'
                        results[port]['product'] = 'SMTP'
                    elif port == 110:
                        results[port]['name'] = 'pop3'
                        results[port]['product'] = 'POP3'
                    elif port == 143:
                        results[port]['name'] = 'imap'
                        results[port]['product'] = 'IMAP'
                    elif port == 3306:
                        results[port]['name'] = 'mysql'
                        results[port]['product'] = 'MySQL'
                    elif port == 3389:
                        results[port]['name'] = 'rdp'
                        results[port]['product'] = 'RDP'
                    elif port == 135:
                        results[port]['name'] = 'msrpc'
                        results[port]['product'] = 'Microsoft RPC'
                    elif port == 445:
                        results[port]['name'] = 'microsoft-ds'
                        results[port]['product'] = 'Microsoft Directory Services'
            
            # Debug: Son sonuçları göster
            self.logger.info(f"Sonuçlar: {results}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap taraması sırasında hata: {str(e)}")
            return {}
            
    async def _banner_grab(self, target_ip: str, port: int, protocol: str) -> Optional[str]:
        """Banner grabbing yapar."""
        try:
            def grab():
                if protocol == 'tcp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target_ip, port))
                    banner = sock.recv(1024)
                    sock.close()
                    return banner.decode('utf-8', errors='ignore').strip()
                return None
                
            banner = await asyncio.get_event_loop().run_in_executor(self.executor, grab)
            return banner
            
        except Exception as e:
            self.logger.warning(f"Banner grabbing hatası: {str(e)}")
            return None
            
    async def detect_services(self, target_ip: str, ports: Dict[int, str], protocol: str = 'tcp') -> Dict[int, Dict]:
        """
        Birden fazla port için servis tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (Dict[int, str]): Port numaraları ve durumları
            protocol (str): Protokol ('tcp' veya 'udp')
            
        Returns:
            Dict[int, Dict]: Port numaralarına göre servis bilgileri
        """
        services = {}
        open_ports = [port for port, state in ports.items() if state in ['open', 'open|filtered']]
        
        # Portları gruplara böl
        port_groups = [open_ports[i:i + self.max_workers] for i in range(0, len(open_ports), self.max_workers)]
        
        total_ports = len(open_ports)
        scanned_ports = 0
        
        for group in port_groups:
            # Her grup için eşzamanlı tespit
            tasks = [self.detect_service(target_ip, port, protocol) for port in group]
            group_results = await asyncio.gather(*tasks)
            
            # Sonuçları birleştir
            for port, service_info in zip(group, group_results):
                services[port] = service_info
                
            # İlerleme durumunu güncelle
            scanned_ports += len(group)
            progress = (scanned_ports / total_ports) * 100
            self.logger.debug(f"Servis tespiti ilerlemesi: {progress:.1f}% ({scanned_ports}/{total_ports})")
                
        return services
        
    def __del__(self):
        """ThreadPoolExecutor'ı temizle."""
        self.executor.shutdown(wait=False)
        # Önbelleği temizle
        self._service_cache.clear()
