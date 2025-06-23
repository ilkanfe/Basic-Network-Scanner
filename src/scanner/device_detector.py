import socket
import struct
import re
from typing import Dict, Tuple, Optional
import subprocess
import platform
from src.utils.logger import setup_logger

class DeviceDetector:
    def __init__(self):
        """Cihaz tespit sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        self.mac_vendors = {
            '00:11:22': 'TP-Link',
            '00:50:56': 'VMware',
            '00:1A:2B': 'HP',
            '00:0C:29': 'VMware',
            '00:1D:7D': 'Apple',
            '00:25:00': 'Cisco',
            '00:26:08': 'HTC',
            '00:50:0F': 'Nortel',
            '00:90:0B': 'Cisco',
            '00:A0:40': 'Cisco',
            '00:B0:64': 'Cisco',
            '00:D0:58': 'Cisco',
            '00:E0:14': 'Cisco',
            '00:F0:1F': 'Cisco',
            '08:00:27': 'VirtualBox',
            '00:1B:63': 'Apple',
            '00:1C:B3': 'Apple',
            '00:1D:4F': 'Apple',
            '00:1E:52': 'Apple',
            '00:1F:5B': 'Apple',
            '00:1F:F3': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:25:00': 'Apple',
            '00:26:08': 'Apple',
            '00:26:B0': 'Apple',
            '00:26:BB': 'Apple',
            '00:30:65': 'Apple',
            '00:50:E4': 'Apple',
            '00:60:97': 'Apple',
            '00:90:27': 'Apple',
            '00:A0:40': 'Apple',
            '00:B0:34': 'Apple',
            '00:D0:58': 'Apple',
            '00:E0:14': 'Apple',
            '00:F0:1F': 'Apple',
            '00:17:88': 'Philips',
            '00:1B:63': 'Philips',
            '00:1C:B3': 'Philips',
            '00:1D:4F': 'Philips',
            '00:1E:52': 'Philips',
            '00:1F:5B': 'Philips',
            '00:1F:F3': 'Philips',
            '00:23:12': 'Philips',
            '00:23:32': 'Philips',
            '00:25:00': 'Philips',
            '00:26:08': 'Philips',
            '00:26:B0': 'Philips',
            '00:26:BB': 'Philips',
            '00:30:65': 'Philips',
            '00:50:E4': 'Philips',
            '00:60:97': 'Philips',
            '00:90:27': 'Philips',
            '00:A0:40': 'Philips',
            '00:B0:34': 'Philips',
            '00:D0:58': 'Philips',
            '00:E0:14': 'Philips',
            '00:F0:1F': 'Philips'
        }
        self.os_type = platform.system().lower()
        
    def get_mac_address(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """
        IP adresine göre MAC adresini ve üreticiyi bulur.
        
        Args:
            ip (str): Hedef IP adresi
            
        Returns:
            Tuple[Optional[str], Optional[str]]: MAC adresi ve üretici bilgisi
        """
        try:
            if self.os_type == "windows":
                # Windows için ARP tablosunu al
                output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
                mac = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
                if mac:
                    mac = mac.group(1).upper()
                    vendor = self.mac_vendors.get(mac[:8], "Bilinmeyen")
                    return mac, vendor
            else:
                # Linux için ARP tablosunu al
                output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
                mac = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
                if mac:
                    mac = mac.group(1).upper()
                    vendor = self.mac_vendors.get(mac[:8], "Bilinmeyen")
                    return mac, vendor
                    
            return None, None
            
        except Exception as e:
            self.logger.error(f"MAC adresi tespiti hatası: {str(e)}")
            return None, None
            
    def detect_device_type(self, ip: str, ports: Dict[int, str]) -> str:
        """
        Port bilgilerine göre cihaz tipini belirler.
        
        Args:
            ip (str): Hedef IP adresi
            ports (Dict[int, str]): Port numaraları ve durumları
            
        Returns:
            str: Cihaz tipi
        """
        try:
            # MAC adresini al
            mac, vendor = self.get_mac_address(ip)
            
            # Port analizi
            open_ports = [port for port, state in ports.items() if state == 'open']
            
            # Yazıcı kontrolü
            if 9100 in open_ports:
                return f"Yazıcı ({vendor})"
                
            # Router kontrolü
            if 80 in open_ports or 443 in open_ports:
                if vendor in ['TP-Link', 'Cisco']:
                    return f"Router ({vendor})"
                    
            # Bilgisayar kontrolü
            if 22 in open_ports or 3389 in open_ports:
                return f"Bilgisayar ({vendor})"
                
            # Telefon kontrolü
            if vendor in ['Apple', 'HTC']:
                return f"Telefon ({vendor})"
                
            # Varsayılan
            return f"Bilinmeyen Cihaz ({vendor})"
            
        except Exception as e:
            self.logger.error(f"Cihaz tespiti hatası: {str(e)}")
            return "Bilinmeyen Cihaz"
            
    def detect_devices(self, ip_list: list, port_results: Dict[str, Dict[int, str]]) -> Dict[str, Dict]:
        """
        Birden fazla IP için cihaz tespiti yapar.
        
        Args:
            ip_list (list): IP adresleri listesi
            port_results (Dict[str, Dict[int, str]]): Port tarama sonuçları
            
        Returns:
            Dict[str, Dict]: Cihaz bilgileri
        """
        devices = {}
        
        for ip in ip_list:
            if ip in port_results:
                mac, vendor = self.get_mac_address(ip)
                device_type = self.detect_device_type(ip, port_results[ip])
                
                devices[ip] = {
                    'mac': mac,
                    'vendor': vendor,
                    'type': device_type,
                    'ports': port_results[ip]
                }
                
        return devices

    def detect_device(self, ip_address: str) -> Dict[str, str]:
        """
        Verilen IP adresine sahip cihazın tipini ve MAC adresini tespit eder.
        
        Args:
            ip_address: Tespit edilecek cihazın IP adresi
            
        Returns:
            Dict[str, str]: Cihaz tipi ve MAC adresi bilgilerini içeren sözlük
        """
        device_type = self._detect_device_type(ip_address)
        mac_address = self._get_mac_address(ip_address)
        
        return {
            "type": device_type,
            "mac_address": mac_address
        }

    def _detect_device_type(self, ip_address: str) -> str:
        """
        Verilen IP adresine sahip cihazın tipini tespit eder.
        
        Args:
            ip_address: Tespit edilecek cihazın IP adresi
            
        Returns:
            str: Cihaz tipi (örn. "Windows PC", "Router", "Unknown")
        """
        if self.os_type == "windows":
            return self._detect_windows_device(ip_address)
        elif self.os_type == "linux":
            return self._detect_linux_device(ip_address)
        else:
            return "Unknown"

    def _detect_windows_device(self, ip_address: str) -> str:
        """
        Windows sistemlerde cihaz tipini tespit eder.
        
        Args:
            ip_address: Tespit edilecek cihazın IP adresi
            
        Returns:
            str: Cihaz tipi
        """
        try:
            # Ping atarak cihazın aktif olup olmadığını kontrol et
            ping_result = subprocess.run(
                ["ping", "-n", "1", ip_address],
                capture_output=True,
                text=True
            )
            
            if "TTL=" in ping_result.stdout:
                # TTL değerine göre cihaz tipini belirle
                if "TTL=128" in ping_result.stdout:
                    return "Windows PC"
                elif "TTL=64" in ping_result.stdout:
                    return "Linux/Unix Device"
                elif "TTL=255" in ping_result.stdout:
                    return "Router"
                else:
                    return "Unknown Device"
            else:
                return "Device Not Responding"
                
        except Exception as e:
            print(f"Cihaz tespiti sırasında hata: {str(e)}")
            return "Error Detecting Device"

    def _detect_linux_device(self, ip_address: str) -> str:
        """
        Linux sistemlerde cihaz tipini tespit eder.
        
        Args:
            ip_address: Tespit edilecek cihazın IP adresi
            
        Returns:
            str: Cihaz tipi
        """
        try:
            # Ping atarak cihazın aktif olup olmadığını kontrol et
            ping_result = subprocess.run(
                ["ping", "-c", "1", ip_address],
                capture_output=True,
                text=True
            )
            
            if "ttl=" in ping_result.stdout.lower():
                # TTL değerine göre cihaz tipini belirle
                if "ttl=128" in ping_result.stdout.lower():
                    return "Windows PC"
                elif "ttl=64" in ping_result.stdout.lower():
                    return "Linux/Unix Device"
                elif "ttl=255" in ping_result.stdout.lower():
                    return "Router"
                else:
                    return "Unknown Device"
            else:
                return "Device Not Responding"
                
        except Exception as e:
            print(f"Cihaz tespiti sırasında hata: {str(e)}")
            return "Error Detecting Device"

    def _get_mac_address(self, ip_address: str) -> str:
        """
        Verilen IP adresine sahip cihazın MAC adresini tespit eder.
        
        Args:
            ip_address: MAC adresi tespit edilecek cihazın IP adresi
            
        Returns:
            str: MAC adresi veya "Unknown" if tespit edilemezse
        """
        try:
            if self.os_type == "windows":
                # Windows'ta arp -a komutunu çalıştır
                result = subprocess.run(
                    ["arp", "-a", ip_address],
                    capture_output=True,
                    text=True
                )
                
                # MAC adresini regex ile bul
                mac_pattern = r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
                match = re.search(mac_pattern, result.stdout)
                
                if match:
                    return match.group(1)
                else:
                    return "Unknown"
                    
            elif self.os_type == "linux":
                # Linux'ta arp -n komutunu çalıştır
                result = subprocess.run(
                    ["arp", "-n", ip_address],
                    capture_output=True,
                    text=True
                )
                
                # MAC adresini regex ile bul
                mac_pattern = r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
                match = re.search(mac_pattern, result.stdout)
                
                if match:
                    return match.group(1)
                else:
                    return "Unknown"
            else:
                return "Unsupported OS"
                
        except Exception as e:
            print(f"MAC adresi tespiti sırasında hata: {str(e)}")
            return "Error Detecting MAC"

    def get_all_devices_from_arp(self) -> list:
        """
        ARP tablosundaki tüm cihazların IP ve MAC adreslerini döndürür.
        """
        devices = []
        try:
            if self.os_type == "windows":
                output = subprocess.check_output("arp -a", shell=True).decode()
                pattern = r"([0-9]+(?:\.[0-9]+){3})\s+([0-9A-Fa-f-]{17})"
                matches = re.findall(pattern, output)
                for ip, mac in matches:
                    devices.append({"ip": ip, "mac": mac.upper()})
            else:
                output = subprocess.check_output("arp -n", shell=True).decode()
                pattern = r"([0-9]+(?:\.[0-9]+){3})\s+.*?\s+([0-9A-Fa-f:]{17})"
                matches = re.findall(pattern, output)
                for ip, mac in matches:
                    devices.append({"ip": ip, "mac": mac.upper()})
        except Exception as e:
            print(f"ARP tablosu okunurken hata: {e}")
        return devices 