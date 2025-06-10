import nmap
import asyncio
import logging
from typing import Dict, List
from src.utils.network_utils import get_mac_and_vendor, get_vendor

class NetworkDiscovery:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
        
    async def discover_devices(self, network_range: str = "192.168.1.0/24") -> List[Dict]:
        """
        Ağdaki cihazları keşfeder.
        
        Args:
            network_range (str): Taranacak ağ aralığı (örn: "192.168.1.0/24")
            
        Returns:
            List[Dict]: Keşfedilen cihazların listesi
        """
        try:
            # Nmap taraması yap
            self.nm.scan(hosts=network_range, arguments='-sn')
            
            discovered_devices = []
            
            # Keşfedilen cihazları işle
            for host in self.nm.all_hosts():
                device_info = {
                    'ip': host,
                    'mac': None,
                    'vendor': None,
                    'hostname': None,
                    'status': 'up'
                }
                
                # Önce Nmap çıktısından MAC ve vendor al
                mac_found = False
                try:
                    mac_info = self.nm[host]['addresses']
                    if 'mac' in mac_info:
                        device_info['mac'] = mac_info['mac']
                        mac_found = True
                        # MAC adresinden vendor bilgisini güncelle
                        vendor = get_vendor(mac_info['mac'])
                        device_info['vendor'] = vendor
                except:
                    pass
                # Eğer MAC bulunamadıysa scapy ile ARP isteği gönder
                if not mac_found:
                    mac, vendor = get_mac_and_vendor(host)
                    if mac:
                        device_info['mac'] = mac
                        device_info['vendor'] = vendor if vendor and vendor != "Bilinmeyen Üretici" else "Üretici bulunamadı"
                    else:
                        device_info['vendor'] = "MAC adresi bulunamadı"
                # Hostname bilgisini al
                try:
                    hostname_info = self.nm[host]['hostnames']
                    if hostname_info:
                        device_info['hostname'] = hostname_info[0]['name']
                except:
                    pass
                
                discovered_devices.append(device_info)
            
            return discovered_devices
            
        except Exception as e:
            self.logger.error(f"Ağ keşfi sırasında hata: {str(e)}")
            return []
            
    async def scan_device(self, ip: str) -> Dict:
        """
        Belirli bir cihazı detaylı tarar.
        
        Args:
            ip (str): Taranacak IP adresi
            
        Returns:
            Dict: Tarama sonuçları
        """
        try:
            # Hızlı port taraması yap
            self.nm.scan(ip, arguments='-F -T4')
            
            scan_results = {
                'ip': ip,
                'status': 'up',
                'open_ports': [],
                'os_info': None
            }
            
            # Açık portları topla
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    ports = self.nm[ip][proto].keys()
                    for port in ports:
                        state = self.nm[ip][proto][port]['state']
                        if state == 'open':
                            service = self.nm[ip][proto][port].get('name', 'unknown')
                            scan_results['open_ports'].append({
                                'port': port,
                                'service': service
                            })
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Cihaz taraması sırasında hata: {str(e)}")
            return {'ip': ip, 'status': 'error', 'error': str(e)} 