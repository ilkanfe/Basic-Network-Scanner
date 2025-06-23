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
import re

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
        
    async def detect_os(self, target: str) -> Dict:
        """Hedef sistemin işletim sistemini tespit eder"""
        try:
            # TTL analizi
            ttl_result = await self._analyze_ttl(target)
            
            # TCP stack analizi
            stack_result = await self._analyze_tcp_stack(target)
            
            # Sonuçları birleştir
            os_info = {
                'name': 'Bilinmiyor',
                'confidence': 0.0,
                'ttl_analysis': ttl_result,
                'stack_analysis': stack_result
            }
            
            # TTL ve stack analizlerini değerlendir
            if ttl_result.get('os') != 'Bilinmiyor':
                os_info['name'] = ttl_result['os']
                os_info['confidence'] += 0.5
                
            if stack_result.get('behavior') != 'Bilinmiyor':
                if os_info['name'] == stack_result['behavior']:
                    os_info['confidence'] += 0.5
                else:
                    os_info['name'] = stack_result['behavior']
                    os_info['confidence'] = 0.5
            
            # Eğer OS adı hala 'Bilinmiyor' ise, 'filtered' olarak işaretle
            if os_info['name'] == 'Bilinmiyor':
                os_info['name'] = 'filtered'
            
            return os_info
            
        except Exception as e:
            self.logger.warning(f"OS tespiti sırasında hata: {str(e)}")
            return {
                'name': 'filtered',
                'confidence': 0.0,
                'ttl_analysis': {'os': 'Bilinmiyor', 'error': str(e)},
                'stack_analysis': {'behavior': 'Bilinmiyor', 'error': str(e)}
            }
            
    async def _analyze_ttl(self, target: str) -> Dict:
        """TTL değerine göre işletim sistemini analiz eder"""
        try:
            # ICMP ping gönder
            ping_result = await self._send_ping(target)
            
            if ping_result is None:
                return {'os': 'Bilinmiyor', 'error': 'Ping yanıtı alınamadı'}
                
            ttl = ping_result.get('ttl', 0)
            
            # TTL değerine göre işletim sistemini belirle
            if 0 < ttl <= 64:
                return {'os': 'Linux/Unix', 'ttl': ttl}
            elif 64 < ttl <= 128:
                return {'os': 'Windows', 'ttl': ttl}
            elif 128 < ttl <= 255:
                return {'os': 'Solaris/AIX', 'ttl': ttl}
            else:
                return {'os': 'Bilinmiyor', 'ttl': ttl}
                
        except asyncio.TimeoutError:
            self.logger.warning(f"TTL analizi zaman aşımına uğradı: {target}")
            return {'os': 'Bilinmiyor', 'error': 'TTL analizi zaman aşımına uğradı'}
        except Exception as e:
            self.logger.warning(f"TTL analizi hatası: {str(e)}")
            return {'os': 'Bilinmiyor', 'error': str(e)}
            
    async def _send_ping(self, target: str) -> Optional[Dict]:
        """ICMP ping gönderir ve yanıtı bekler"""
        try:
            # Windows'ta ping komutunu çalıştır
            process = await asyncio.create_subprocess_shell(
                f"ping -n 1 -w 1000 {target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # TTL değerini çıktıdan çıkar
                output = stdout.decode()
                ttl_match = re.search(r'TTL=(\d+)', output)
                if ttl_match:
                    return {'ttl': int(ttl_match.group(1))}
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Ping gönderme hatası: {str(e)}")
            return None
            
    async def _analyze_tcp_stack(self, target: str) -> Dict:
        """TCP stack davranışını analiz eder"""
        try:
            # TCP SYN paketi gönder
            syn_packet = IP(dst=target)/TCP(dport=80, flags="S")
            response = sr1(syn_packet, timeout=2, verbose=0)
            
            if response is None:
                return {'behavior': 'Bilinmiyor', 'error': 'Yanıt alınamadı'}
                
            # TCP stack davranışını analiz et
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    return {'behavior': 'Linux/Unix', 'details': 'SYN-ACK yanıtı'}
                elif response[TCP].flags == 0x14:  # RST-ACK
                    return {'behavior': 'Windows', 'details': 'RST-ACK yanıtı'}
                else:
                    return {'behavior': 'Bilinmiyor', 'details': 'Bilinmeyen TCP yanıtı'}
            else:
                return {'behavior': 'Bilinmiyor', 'details': 'TCP yanıtı yok'}
                
        except Exception as e:
            self.logger.warning(f"TCP stack analizi hatası: {str(e)}")
            return {'behavior': 'Bilinmiyor', 'error': str(e)}
            
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