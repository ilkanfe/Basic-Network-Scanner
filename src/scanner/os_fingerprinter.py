import nmap
import socket
import struct
import platform
import asyncio
from typing import Dict, Optional, Tuple
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error
from scapy.all import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
        
        # Genişletilmiş bir OS parmak izi veritabanı
        self.OS_FINGERPRINTS = {
            "Windows": {
                "TTL": [64, 128],  # Windows genellikle 128 kullanır, eski versiyonlar 64
                "WINDOW_SIZE": [65535, 8192, 16384, 16383, 16388, 32767, 32120, 65536], # Windows'un farklı versiyonları ve yamaları
                "TCP_OPTIONS": ["MSS", "NOP", "WS", "NOP", "NOP", "TS", "SACK_PERM", "EOL"]
            },
            "Linux": {
                "TTL": [64], # Çoğu Linux dağıtımı 64 TTL kullanır
                "WINDOW_SIZE": [5840, 5792, 65535, 14600, 16384, 29200], # Linux çekirdek sürümlerine göre değişir
                "TCP_OPTIONS": ["MSS", "SACK_PERM", "TS", "NOP", "WS", "NOP", "NOP"]
            },
            "macOS": {
                "TTL": [64], # macOS genellikle 64 TTL kullanır
                "WINDOW_SIZE": [65535, 131072, 16384], # Farklı macOS sürümleri
                "TCP_OPTIONS": ["MSS", "NOP", "WS", "NOP", "NOP", "TS", "SACK_PERM"]
            },
            "FreeBSD": {
                "TTL": [64], # FreeBSD genellikle 64 TTL kullanır
                "WINDOW_SIZE": [65535, 33600], # Farklı FreeBSD sürümleri
                "TCP_OPTIONS": ["MSS", "NOP", "WS", "TS", "SACK_PERM", "EOL"]
            },
            "Cisco IOS": {
                "TTL": [255], # Cisco IOS genellikle 255 TTL kullanır
                "WINDOW_SIZE": [4128, 4129, 4280], # Farklı Cisco cihazları
                "TCP_OPTIONS": ["MSS", "NOP", "WS", "TS"]
            },
            "Android": {
                "TTL": [64], # Android genellikle 64 TTL kullanır
                "WINDOW_SIZE": [65535, 29200], # Android versiyonlarına göre değişir
                "TCP_OPTIONS": ["MSS", "SACK_PERM", "TS", "NOP", "WS", "NOP", "NOP"]
            },
            "iOS": {
                "TTL": [64], # iOS genellikle 64 TTL kullanır
                "WINDOW_SIZE": [65535, 32767], # iOS versiyonlarına göre değişir
                "TCP_OPTIONS": ["MSS", "NOP", "WS", "NOP", "NOP", "TS", "SACK_PERM"]
            },
            "Printer": {
                "TTL": [64, 128, 255], # Yazıcılar farklı TTL'ler kullanabilir
                "WINDOW_SIZE": [512, 1024, 2048, 4096, 8192], # Basit cihazlar için küçük pencere boyutları
                "TCP_OPTIONS": [] # Çoğu basit cihaz TCP seçenekleri kullanmaz
            },
            "Router/Embedded Linux": {
                "TTL": [64, 128], # Routerlar veya gömülü Linux sistemleri farklı TTL'ler kullanabilir
                "WINDOW_SIZE": [5840, 29200, 16384, 65535], # Çeşitli router/gömülü sistemler
                "TCP_OPTIONS": ["MSS", "SACK_PERM", "TS", "NOP", "WS", "NOP", "NOP"]
            }
        }
        
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
                # SYN paketi gönder
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

    def fingerprint_os(self, target_ip, open_port=80):
        """
        Hedef IP adresinin işletim sistemini TCP/IP yığını analizi ile tahmin eder.
        Args:
            target_ip (str): Hedef IP adresi.
            open_port (int): Hedefteki açık olduğu bilinen bir TCP portu (varsayılan: 80).
        Returns:
            str: Tahmin edilen işletim sistemi veya 'Bilinmiyor'.
        """
        try:
            # SYN paketi oluştur
            syn_packet = IP(dst=target_ip)/TCP(dport=open_port, flags="S", options=[('MSS', 1460), ('NOP', None), ('WS', 10), ('NOP', None), ('NOP', None), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')])
            
            # Paketi gönder ve yanıtı bekle
            ans, unans = sr(syn_packet, timeout=2, verbose=0)

            if ans:
                for sent, received in ans:
                    if received.haslayer(TCP) and received[TCP].flags == "SA": # SYN-ACK yanıtı
                        ttl = received[IP].ttl
                        window_size = received[TCP].window
                        
                        # TCP seçeneklerini çıkar
                        tcp_options = []
                        if received[TCP].options:
                            for opt in received[TCP].options:
                                if isinstance(opt, tuple):
                                    if opt[0] == 'MSS':
                                        tcp_options.append("MSS")
                                    elif opt[0] == 'NOP':
                                        tcp_options.append("NOP")
                                    elif opt[0] == 'WScale':
                                        tcp_options.append("WS")
                                    elif opt[0] == 'Timestamp':
                                        tcp_options.append("TS")
                                    elif opt[0] == 'SAckOK':
                                        tcp_options.append("SACK_PERM")
                                    elif opt[0] == 'EOL':
                                        tcp_options.append("EOL")
                                else:
                                    # Diğer basit seçenekler için
                                    if opt == 'NOP':
                                        tcp_options.append("NOP")
                                    elif opt == 'EOL':
                                        tcp_options.append("EOL")

                        # Parmak izi veritabanı ile karşılaştır
                        for os_name, os_data in self.OS_FINGERPRINTS.items():
                            if ttl in os_data["TTL"] and \
                               window_size in os_data["WINDOW_SIZE"] and \
                               all(opt in os_data["TCP_OPTIONS"] for opt in tcp_options): # Tüm alınan seçenekler veritabanında olmalı
                                return os_name
                        return "Bilinmiyor (belirli özellikler eşleşmedi)"
            return "Bilinmiyor (yanıt yok veya SYN-ACK değil)"
        except Exception as e:
            return f"OS Tespiti Hatası: {e}"

if __name__ == '__main__':
    # Örnek kullanım:
    fingerprinter = OSFingerprinter()
    
    # Kendi yerel IP adresinizi veya ağınızdaki bilinen bir cihazın IP'sini kullanın
    # Örn: Linux için 192.168.1.1 (router veya bir Linux sunucu olabilir)
    # Örn: Windows için 192.168.1.102 (kendi Windows bilgisayarınız)
    
    target_ip = "192.168.1.102" # Lütfen kendi ağınızdaki bir IP adresini buraya yazın
    open_port = 80 # Hedefte açık olduğu bilinen bir port

    print(f"{target_ip} adresinin işletim sistemi tahmin ediliyor...")
    os_name = fingerprinter.fingerprint_os(target_ip, open_port)
    print(f"Tahmin edilen İşletim Sistemi: {os_name}") 