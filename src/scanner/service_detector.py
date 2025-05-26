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
            timeout (float): Bağlantı timeout süresi (saniye)
            max_workers (int): Maksimum eşzamanlı işçi sayısı
            max_retries (int): Maksimum yeniden deneme sayısı
            retry_delay (float): Yeniden denemeler arası bekleme süresi (saniye)
        """
        self.logger = setup_logger(__name__)
        self.timeout = timeout
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.cache = {}
        
    @lru_cache(maxsize=1000)
    def _get_cached_service(self, target_ip: str, port: int, protocol: str) -> Optional[Dict]:
        """Önbellekten servis bilgisini alır"""
        key = f"{target_ip}:{port}:{protocol}"
        return self.cache.get(key)
        
    def _cache_service(self, target_ip: str, port: int, protocol: str, service_info: Dict):
        """Servis bilgisini önbelleğe kaydeder"""
        key = f"{target_ip}:{port}:{protocol}"
        self.cache[key] = service_info
        
    async def detect_service(self, target_ip: str, port: int, protocol: str = 'tcp') -> Dict:
        """
        Belirtilen port ve protokol için servis tespiti yapar.
        
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
            self.logger.error(f"Servis tespiti sırasında hata: {str(e)}")
            return {
                'name': 'unknown',
                'product': 'unknown',
                'version': 'unknown',
                'state': 'open',
                'banner': None,
                'detection_time': time.time()
            }
            
    async def _banner_grab(self, target_ip: str, port: int, protocol: str) -> Optional[str]:
        """Banner grabbing yapar"""
        try:
            def grab():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                try:
                    if protocol == 'tcp':
                        sock.connect((target_ip, port))
                        sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                        return sock.recv(1024).decode('utf-8', errors='ignore')
                    else:  # UDP
                        sock.sendto(b"", (target_ip, port))
                        data, _ = sock.recvfrom(1024)
                        return data.decode('utf-8', errors='ignore')
                except socket.timeout:
                    return None
                except socket.error:
                    return None
                finally:
                    sock.close()
                    
            return await asyncio.get_event_loop().run_in_executor(None, grab)
            
        except Exception as e:
            self.logger.error(f"Banner grabbing sırasında hata: {str(e)}")
            return None
            
    async def detect_services(self, target_ip: str, ports: Dict[int, str], protocol: str = 'tcp') -> Dict[int, Dict]:
        """
        Birden fazla port için servis tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (Dict[int, str]): Port numaraları ve durumları
            protocol (str): Protokol ('tcp' veya 'udp')
            
        Returns:
            Dict[int, Dict]: Port numaraları ve servis bilgileri
        """
        results = {}
        
        for port, state in ports.items():
            if state == 'open':
                service_info = await self.detect_service(target_ip, port, protocol)
                results[port] = service_info
                
        return results
        
    def __del__(self):
        """Önbelleği temizle"""
        self.cache.clear()
