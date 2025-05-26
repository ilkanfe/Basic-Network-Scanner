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
        try:
            # Önbellekten kontrol et
            cached_service = self._get_cached_service(target_ip, port, protocol)
            if cached_service:
                return cached_service
                
            # Banner grabbing'i önce yap
            banner = await self._banner_grab(target_ip, port, protocol)
            
            # Banner'ın sadece ilk satırını al
            short_banner = banner.splitlines()[0] if banner else None
            service_info = {
                'name': 'unknown',
                'product': 'unknown',
                'version': 'unknown',
                'state': 'open',
                'banner': short_banner,
                'detection_time': time.time()
            }
            
            # Port'a göre varsayılan servis bilgileri
            if port == 22:
                service_info['name'] = 'ssh'
                service_info['product'] = 'SSH'
                if banner and 'SSH-2.0' in banner:
                    service_info['version'] = banner.split('SSH-2.0-')[1].split()[0]
            elif port == 80:
                service_info['name'] = 'http'
                service_info['product'] = 'HTTP'
                if banner and 'Server:' in banner:
                    service_info['version'] = banner.split('Server:')[1].split('\n')[0].strip()
            elif port == 443:
                service_info['name'] = 'https'
                service_info['product'] = 'HTTPS'
                if banner and 'Server:' in banner:
                    service_info['version'] = banner.split('Server:')[1].split('\n')[0].strip()
                elif banner == "HTTPS Service Detected":
                    service_info['version'] = "SSL/TLS"
            elif port == 53:
                service_info['name'] = 'domain'
                service_info['product'] = 'DNS'
            elif port == 21:
                service_info['name'] = 'ftp'
                service_info['product'] = 'FTP'
                if banner:
                    service_info['version'] = banner.split()[0]
            elif port == 25:
                service_info['name'] = 'smtp'
                service_info['product'] = 'SMTP'
                if banner:
                    service_info['version'] = banner.split()[0]
            elif port == 135:
                service_info['name'] = 'msrpc'
                service_info['product'] = 'Microsoft RPC'
                service_info['version'] = 'Windows'
            elif port == 139:
                service_info['name'] = 'netbios-ssn'
                service_info['product'] = 'NetBIOS'
                service_info['version'] = 'Windows'
            elif port == 445:
                service_info['name'] = 'microsoft-ds'
                service_info['product'] = 'SMB'
                service_info['version'] = 'Windows'
            elif port == 3389:
                service_info['name'] = 'rdp'
                service_info['product'] = 'Remote Desktop'
                service_info['version'] = 'Windows'
            elif port == 1433:
                service_info['name'] = 'ms-sql-s'
                service_info['product'] = 'Microsoft SQL Server'
                service_info['version'] = 'Windows'
            elif port == 3306:
                service_info['name'] = 'mysql'
                service_info['product'] = 'MySQL'
                if banner:
                    service_info['version'] = banner.split()[0]
            elif port == 5432:
                service_info['name'] = 'postgresql'
                service_info['product'] = 'PostgreSQL'
                if banner:
                    service_info['version'] = banner.split()[0]
            elif port == 27017:
                service_info['name'] = 'mongodb'
                service_info['product'] = 'MongoDB'
                if banner:
                    service_info['version'] = banner.split()[0]
            elif port == 8080:
                service_info['name'] = 'http-proxy'
                service_info['product'] = 'HTTP Proxy'
                if banner and 'Server:' in banner:
                    service_info['version'] = banner.split('Server:')[1].split('\n')[0].strip()
            
            # Önbelleğe kaydet
            self._cache_service(target_ip, port, protocol, service_info)
            
            return service_info
            
        except Exception as e:
            return {
                'name': 'unknown',
                'product': 'unknown',
                'version': 'unknown',
                'state': 'open',
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
            
            # Komutu çalıştır
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {}
            
            # Nmap çıktısını parse et
            results = {}
            current_port = None
            
            # Port ve servis bilgilerini bul
            for line in stdout.decode('latin-1').split('\n'):
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
                    except (ValueError, IndexError):
                        continue
                
                # Servis bilgilerini bul
                if current_port and 'Service Info:' in line:
                    info = line.split('Service Info:')[1].strip()
                    if ';' in info:
                        service, version = info.split(';', 1)
                        results[current_port]['name'] = service.strip()
                        results[current_port]['version'] = version.strip()
                    else:
                        results[current_port]['name'] = info.strip()
                
                # Banner bilgisini bul
                if current_port and 'Banner:' in line:
                    banner = line.split('Banner:')[1].strip()
                    results[current_port]['banner'] = banner
            
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
            
            return results
            
        except Exception as e:
            return {}
            
    async def _banner_grab(self, target_ip: str, port: int, protocol: str) -> Optional[str]:
        """Banner grabbing yapar."""
        try:
            def grab():
                if protocol == 'tcp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target_ip, port))
                    
                    # Port'a göre özel banner grabbing
                    if port == 22:  # SSH
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                    elif port == 80:  # HTTP
                        sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                    elif port == 443:  # HTTPS
                        try:
                            import ssl
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            ssl_sock = context.wrap_socket(sock, server_hostname=target_ip)
                            ssl_sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                            banner = ssl_sock.recv(1024)
                            ssl_sock.close()
                            return banner.decode('utf-8', errors='ignore').strip()
                        except:
                            return "HTTPS Service Detected"
                    elif port == 21:  # FTP
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                    elif port == 25:  # SMTP
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                    else:
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                        
                return None
                
            banner = await asyncio.get_event_loop().run_in_executor(self.executor, grab)
            return banner
            
        except Exception as e:
            return None
            
    async def detect_services(self, target_ip: str, ports: Dict[int, str], protocol: str = 'tcp') -> Dict[int, Dict]:
        services = {}
        open_ports = [port for port, state in ports.items() if state in ['open', 'open|filtered']]
        
        if not open_ports:
            print("\nAçık port bulunamadı!")
            return services
            
        print("\nServis Tespiti Başlatılıyor...")
        print("-" * 50)
        
        port_groups = [open_ports[i:i + self.max_workers] for i in range(0, len(open_ports), self.max_workers)]
        
        total_ports = len(open_ports)
        scanned_ports = 0
        
        for group in port_groups:
            tasks = [self.detect_service(target_ip, port, protocol) for port in group]
            group_results = await asyncio.gather(*tasks)
            
            for port, service_info in zip(group, group_results):
                services[port] = service_info
                if service_info['name'] != 'unknown':
                    print(f"\nPort {port}:")
                    print(f"  Servis: {service_info['name']}")
                    print(f"  Ürün: {service_info['product']}")
                    if service_info['version'] != 'unknown':
                        print(f"  Versiyon: {service_info['version']}")
                    if service_info['banner']:
                        print(f"  Banner: {service_info['banner']}")  # Sadece ilk satır
                    print("-" * 30)
                
            scanned_ports += len(group)
            progress = (scanned_ports / total_ports) * 100
            print(f"\rServis Tespiti İlerlemesi: {progress:.1f}% ({scanned_ports}/{total_ports})", end="")
            
        print("\n" + "-" * 50)
        print("\nServis Tespiti Tamamlandı!")
        return services
        
    def __del__(self):
        """ThreadPoolExecutor'ı temizle."""
        self.executor.shutdown(wait=False)
        # Önbelleği temizle
        self._service_cache.clear()
