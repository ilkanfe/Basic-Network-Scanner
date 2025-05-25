import nmap
import socket
import struct
import platform
import asyncio
from typing import Dict, Optional, Tuple
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error

class OSFingerprinter:
    def __init__(self, timeout: float = 2.0):
        """
        OS Fingerprinting sınıfı başlatıcısı.
        
        Args:
            timeout (float): Timeout süresi (saniye)
        """
        self.logger = setup_logger(__name__)
        self.nm = nmap.PortScanner()
        self.timeout = timeout
        
    async def detect_os(self, target_ip: str) -> Dict:
        """
        Hedef IP'nin işletim sistemini tespit eder.
        
        Args:
            target_ip (str): Hedef IP adresi
            
        Returns:
            Dict: OS bilgileri
        """
        try:
            # Nmap OS tespiti
            nmap_result = await self._nmap_os_detection(target_ip)
            
            # TTL analizi
            ttl_info = await self._analyze_ttl(target_ip)
            
            # TCP/IP stack analizi
            stack_info = await self._analyze_tcp_stack(target_ip)
            
            # Sonuçları birleştir
            os_info = {
                'name': nmap_result.get('name', 'unknown'),
                'accuracy': nmap_result.get('accuracy', 0),
                'type': nmap_result.get('type', 'unknown'),
                'ttl_analysis': ttl_info,
                'stack_analysis': stack_info,
                'confidence': self._calculate_confidence(nmap_result, ttl_info, stack_info)
            }
            
            return os_info
            
        except Exception as e:
            error_msg = f"OS tespiti başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            return {
                'name': 'unknown',
                'accuracy': 0,
                'type': 'unknown',
                'ttl_analysis': None,
                'stack_analysis': None,
                'confidence': 0
            }
            
    async def _nmap_os_detection(self, target_ip: str) -> Dict:
        """Nmap ile OS tespiti yapar."""
        try:
            def scan():
                self.nm.scan(target_ip, arguments='-O')
                if target_ip in self.nm.all_hosts():
                    return self.nm[target_ip].get('osmatch', [{}])[0]
                return {}
                
            result = await asyncio.get_event_loop().run_in_executor(None, scan)
            return result
            
        except Exception as e:
            self.logger.warning(f"Nmap OS tespiti hatası: {str(e)}")
            return {}
            
    async def _analyze_ttl(self, target_ip: str) -> Dict:
        """TTL değerini analiz eder."""
        try:
            def ping():
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(self.timeout)
                
                # ICMP echo request paketi oluştur
                packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0)
                sock.sendto(packet, (target_ip, 0))
                
                # Yanıtı al
                data, addr = sock.recvfrom(1024)
                ttl = struct.unpack('!B', data[8:9])[0]
                
                # TTL değerine göre OS tahmini
                if ttl <= 64:
                    return {'os': 'Linux/Unix', 'ttl': ttl}
                elif ttl <= 128:
                    return {'os': 'Windows', 'ttl': ttl}
                else:
                    return {'os': 'Unknown', 'ttl': ttl}
                    
            result = await asyncio.get_event_loop().run_in_executor(None, ping)
            return result
            
        except Exception as e:
            self.logger.warning(f"TTL analizi hatası: {str(e)}")
            return {'os': 'Unknown', 'ttl': None}
            
    async def _analyze_tcp_stack(self, target_ip: str) -> Dict:
        """TCP/IP stack davranışını analiz eder."""
        try:
            def analyze():
                # TCP SYN paketi gönder
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # TCP bağlantı davranışını analiz et
                try:
                    sock.connect((target_ip, 80))
                    sock.close()
                    return {'behavior': 'standard', 'details': 'Normal TCP handshake'}
                except socket.timeout:
                    return {'behavior': 'filtered', 'details': 'Connection timeout'}
                except ConnectionRefusedError:
                    return {'behavior': 'closed', 'details': 'Port closed'}
                    
            result = await asyncio.get_event_loop().run_in_executor(None, analyze)
            return result
            
        except Exception as e:
            self.logger.warning(f"TCP stack analizi hatası: {str(e)}")
            return {'behavior': 'unknown', 'details': str(e)}
            
    def _calculate_confidence(self, nmap_result: Dict, ttl_info: Dict, stack_info: Dict) -> float:
        """OS tespiti için güven skorunu hesaplar."""
        confidence = 0.0
        
        # Nmap sonuçlarına göre güven skoru
        if nmap_result.get('accuracy'):
            confidence += float(nmap_result['accuracy']) * 0.6
            
        # TTL analizine göre güven skoru
        if ttl_info.get('os') != 'Unknown':
            confidence += 0.2
            
        # TCP stack analizine göre güven skoru
        if stack_info.get('behavior') == 'standard':
            confidence += 0.2
            
        return min(confidence, 1.0) 