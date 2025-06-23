import nmap
import socket
import asyncio
import ssl
import OpenSSL
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Set, List, Tuple
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
            if protocol == 'udp':
                if port == 53:
                    service_info['name'] = 'domain'
                    service_info['product'] = 'DNS'
                    if banner and 'dns' in banner.lower():
                        service_info['version'] = 'Detected'
                elif port == 123:
                    service_info['name'] = 'ntp'
                    service_info['product'] = 'NTP'
                    if banner and 'ntp' in banner.lower():
                        service_info['version'] = 'Detected'
                elif port == 161:
                    service_info['name'] = 'snmp'
                    service_info['product'] = 'SNMP'
                    if banner and 'snmp' in banner.lower():
                        service_info['version'] = 'Detected'
                elif port == 67 or port == 68:
                    service_info['name'] = 'dhcp'
                    service_info['product'] = 'DHCP'
                elif port == 69:
                    service_info['name'] = 'tftp'
                    service_info['product'] = 'TFTP'
                elif port == 514:
                    service_info['name'] = 'syslog'
                    service_info['product'] = 'Syslog'
                elif port == 1812 or port == 1813:
                    service_info['name'] = 'radius'
                    service_info['product'] = 'RADIUS'
                elif port == 5060:
                    service_info['name'] = 'sip'
                    service_info['product'] = 'SIP'
                elif port == 69:
                    service_info['name'] = 'tftp'
                    service_info['product'] = 'TFTP'
                # Diğer UDP portları için banner varsa ekle
                if banner:
                    service_info['banner'] = banner[:100]
            else:
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

    async def check_security(self, target_ip: str, port: int, service_info: Dict) -> Dict:
        """
        Servis güvenlik kontrolü yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            port (int): Port numarası
            service_info (Dict): Servis bilgileri
            
        Returns:
            Dict: Güvenlik kontrol sonuçları
        """
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,  # 0-100 arası güvenlik puanı
            'recommendations': []
        }
        
        try:
            # SSL/TLS kontrolü
            if port in [443, 8443] or service_info['name'] in ['https', 'ssl']:
                ssl_info = await self._check_ssl_security(target_ip, port)
                security_info['vulnerabilities'].extend(ssl_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], ssl_info['security_score'])
                security_info['recommendations'].extend(ssl_info['recommendations'])
            
            # Servis bazlı güvenlik kontrolleri
            if service_info['name'] == 'ssh':
                ssh_info = await self._check_ssh_security(target_ip, port)
                security_info['vulnerabilities'].extend(ssh_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], ssh_info['security_score'])
                security_info['recommendations'].extend(ssh_info['recommendations'])
            
            elif service_info['name'] == 'http':
                http_info = await self._check_http_security(target_ip, port)
                security_info['vulnerabilities'].extend(http_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], http_info['security_score'])
                security_info['recommendations'].extend(http_info['recommendations'])
            
            elif service_info['name'] == 'ftp':
                ftp_info = await self._check_ftp_security(target_ip, port)
                security_info['vulnerabilities'].extend(ftp_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], ftp_info['security_score'])
                security_info['recommendations'].extend(ftp_info['recommendations'])
            
            elif service_info['name'] == 'smtp':
                smtp_info = await self._check_smtp_security(target_ip, port)
                security_info['vulnerabilities'].extend(smtp_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], smtp_info['security_score'])
                security_info['recommendations'].extend(smtp_info['recommendations'])
            
            elif service_info['name'] == 'rdp':
                rdp_info = await self._check_rdp_security(target_ip, port)
                security_info['vulnerabilities'].extend(rdp_info['vulnerabilities'])
                security_info['security_score'] = min(security_info['security_score'], rdp_info['security_score'])
                security_info['recommendations'].extend(rdp_info['recommendations'])
            
            return security_info
            
        except Exception as e:
            self.logger.error(f"Güvenlik kontrolü sırasında hata: {str(e)}")
            return security_info

    async def _check_ssl_security(self, target_ip: str, port: int) -> Dict:
        """SSL/TLS güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target_ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    # Sertifika geçerlilik kontrolü
                    if x509.has_expired():
                        security_info['vulnerabilities'].append('SSL sertifikası süresi dolmuş')
                        security_info['security_score'] -= 20
                        security_info['recommendations'].append('SSL sertifikasını yenileyin')
                    
                    # Protokol versiyonu kontrolü
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        security_info['vulnerabilities'].append(f'Güvensiz SSL/TLS versiyonu: {ssock.version()}')
                        security_info['security_score'] -= 30
                        security_info['recommendations'].append('TLSv1.2 veya TLSv1.3 kullanın')
                    
                    # Şifreleme kontrolü
                    cipher = ssock.cipher()
                    if cipher[0].startswith(('RC4', 'DES', '3DES')):
                        security_info['vulnerabilities'].append(f'Zayıf şifreleme algoritması: {cipher[0]}')
                        security_info['security_score'] -= 25
                        security_info['recommendations'].append('Güçlü şifreleme algoritmaları kullanın')
        
        except Exception as e:
            security_info['vulnerabilities'].append(f'SSL/TLS kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info

    async def _check_ssh_security(self, target_ip: str, port: int) -> Dict:
        """SSH güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # SSH banner'ı al
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # SSH versiyon kontrolü
            if 'SSH-1.99' in banner or 'SSH-1.5' in banner:
                security_info['vulnerabilities'].append('Eski SSH versiyonu kullanılıyor')
                security_info['security_score'] -= 20
                security_info['recommendations'].append('SSH-2.0 kullanın')
            
            # Varsayılan port kontrolü
            if port == 22:
                security_info['vulnerabilities'].append('Varsayılan SSH portu kullanılıyor')
                security_info['security_score'] -= 10
                security_info['recommendations'].append('SSH portunu değiştirin')
            
            sock.close()
            
        except Exception as e:
            security_info['vulnerabilities'].append(f'SSH kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info

    async def _check_http_security(self, target_ip: str, port: int) -> Dict:
        """HTTP güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # HTTP isteği gönder
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            sock.send(request.encode())
            
            # Yanıtı al
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Güvenlik başlıkları kontrolü
            security_headers = {
                'X-Frame-Options': 'Clickjacking koruması eksik',
                'X-Content-Type-Options': 'MIME-type sniffing koruması eksik',
                'X-XSS-Protection': 'XSS koruması eksik',
                'Strict-Transport-Security': 'HSTS başlığı eksik',
                'Content-Security-Policy': 'CSP başlığı eksik'
            }
            
            for header, message in security_headers.items():
                if header not in response:
                    security_info['vulnerabilities'].append(message)
                    security_info['security_score'] -= 10
                    security_info['recommendations'].append(f'{header} başlığını ekleyin')
            
            sock.close()
            
        except Exception as e:
            security_info['vulnerabilities'].append(f'HTTP kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info

    async def _check_ftp_security(self, target_ip: str, port: int) -> Dict:
        """FTP güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # FTP banner'ı al
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Anonim erişim kontrolü
            if 'Anonymous access granted' in banner:
                security_info['vulnerabilities'].append('Anonim FTP erişimi açık')
                security_info['security_score'] -= 30
                security_info['recommendations'].append('Anonim FTP erişimini kapatın')
            
            # Varsayılan port kontrolü
            if port == 21:
                security_info['vulnerabilities'].append('Varsayılan FTP portu kullanılıyor')
                security_info['security_score'] -= 10
                security_info['recommendations'].append('FTP portunu değiştirin')
            
            sock.close()
            
        except Exception as e:
            security_info['vulnerabilities'].append(f'FTP kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info

    async def _check_smtp_security(self, target_ip: str, port: int) -> Dict:
        """SMTP güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # SMTP banner'ı al
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Açık relay kontrolü
            sock.send(b"HELO test.com\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '250' in response:
                sock.send(b"MAIL FROM: <test@test.com>\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in response:
                    security_info['vulnerabilities'].append('SMTP açık relay tespit edildi')
                    security_info['security_score'] -= 40
                    security_info['recommendations'].append('SMTP relay kısıtlamalarını yapılandırın')
            
            sock.close()
            
        except Exception as e:
            security_info['vulnerabilities'].append(f'SMTP kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info

    async def _check_rdp_security(self, target_ip: str, port: int) -> Dict:
        """RDP güvenlik kontrolü yapar"""
        security_info = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # RDP bağlantı isteği gönder
            rdp_request = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            sock.send(rdp_request)
            
            # Yanıtı al
            response = sock.recv(1024)
            
            # NLA kontrolü
            if response[0] == 0x02:  # NLA devre dışı
                security_info['vulnerabilities'].append('Network Level Authentication (NLA) devre dışı')
                security_info['security_score'] -= 30
                security_info['recommendations'].append('RDP için NLA\'yı etkinleştirin')
            
            # Varsayılan port kontrolü
            if port == 3389:
                security_info['vulnerabilities'].append('Varsayılan RDP portu kullanılıyor')
                security_info['security_score'] -= 10
                security_info['recommendations'].append('RDP portunu değiştirin')
            
            sock.close()
            
        except Exception as e:
            security_info['vulnerabilities'].append(f'RDP kontrolü başarısız: {str(e)}')
            security_info['security_score'] -= 10
        
        return security_info
