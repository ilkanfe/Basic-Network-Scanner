from scapy.all import *
import ipaddress
import logging
from typing import List, Dict, Tuple
import time
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error
from src.utils.platform_utils import is_windows, get_platform_specific_command
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
import socket

class PortScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 50):
        """
        Port tarayıcı sınıfı başlatıcısı.
        
        Args:
            timeout (float): Port tarama timeout süresi (saniye)
            max_workers (int): Maksimum eşzamanlı tarama sayısı
        """
        self.logger = setup_logger(__name__)
        self.timeout = timeout
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.scan_results = {}
        
    def scan_ip_range(self, ip_range: str) -> List[str]:
        """
        Belirtilen IP aralığındaki aktif hostları tarar.
        
        Args:
            ip_range (str): CIDR formatında IP aralığı (örn: '192.168.1.0/24')
            
        Returns:
            List[str]: Aktif hostların IP adresleri listesi
        """
        try:
            network = ipaddress.ip_network(ip_range)
            active_hosts = []
            
            for ip in network.hosts():
                ip_str = str(ip)
                if is_windows():
                    # Windows'ta ICMP ping kullan
                    ping_cmd = get_platform_specific_command('ping')
                    response = os.system(f"{ping_cmd} {ip_str} > nul")
                    if response == 0:
                        active_hosts.append(ip_str)
                        self.logger.info(f"Aktif host bulundu: {ip_str}")
                else:
                    # Linux'ta ARP ping kullan
                    arp_request = ARP(pdst=ip_str)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast/arp_request
                    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                    if answered_list:
                        active_hosts.append(ip_str)
                        self.logger.info(f"Aktif host bulundu: {ip_str}")
            
            return active_hosts
            
        except Exception as e:
            error_msg = f"IP aralığı taraması başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            raise ValueError(f"IP aralığı taraması başarısız oldu: {str(e)}")
    
    async def scan_ports(self, target: str, start_port: int, end_port: int, scan_type: str = "tcp") -> Dict[int, str]:
        """
        Belirtilen port aralığını tarar.
        
        Args:
            target (str): Hedef IP adresi
            start_port (int): Başlangıç portu
            end_port (int): Bitiş portu
            scan_type (str): Tarama tipi ("tcp" veya "udp")
            
        Returns:
            Dict[int, str]: Port numaraları ve durumları
        """
        self.logger.info(f"Port taraması başlatılıyor: {target} ({start_port}-{end_port})")
        
        try:
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError("Port numaraları 1-65535 arasında olmalıdır")
            if start_port > end_port:
                raise ValueError("Başlangıç portu bitiş portundan büyük olamaz")
                
            ports = list(range(start_port, end_port + 1))
            port_groups = [ports[i:i + self.max_workers] for i in range(0, len(ports), self.max_workers)]
            
            results = {}
            total_ports = len(ports)
            scanned_ports = 0
            
            print(f"\nHedef: {target}")
            print(f"Tarama Tipi: {scan_type.upper()}")
            print(f"Port Aralığı: {start_port}-{end_port}")
            print("-" * 50)
            
            for group in port_groups:
                tasks = [self.scan_port(target, port, scan_type) for port in group]
                group_results = await asyncio.gather(*tasks)
                
                for port, state in zip(group, group_results):
                    results[port] = state
                    if state == "open":
                        print(f"Port {port}: AÇIK")
                
                scanned_ports += len(group)
                progress = (scanned_ports / total_ports) * 100
                print(f"\rTarama İlerlemesi: {progress:.1f}% ({scanned_ports}/{total_ports})", end="")
            
            print("\n" + "-" * 50)
            open_count = sum(1 for state in results.values() if state == 'open')
            print(f"\nTarama Tamamlandı!")
            print(f"Toplam Açık Port: {open_count}")
            print(f"Toplam Kapalı Port: {len(results) - open_count}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Port taraması sırasında hata: {str(e)}")
            raise
            
    async def scan_port(self, target: str, port: int, scan_type: str = "tcp") -> str:
        """
        Tek bir portu tarar.
        
        Args:
            target (str): Hedef IP adresi
            port (int): Port numarası
            scan_type (str): Tarama tipi ("tcp" veya "udp")
            
        Returns:
            str: Port durumu ("open", "closed", "filtered")
        """
        try:
            if scan_type == "tcp":
                return await self._tcp_connect_scan(target, port)
            elif scan_type == "udp":
                return await self._udp_scan(target, port)
            else:
                raise ValueError(f"Geçersiz tarama tipi: {scan_type}")
                
        except Exception as e:
            self.logger.error(f"Port {port} taraması sırasında hata: {str(e)}")
            return "filtered"
            
    async def _tcp_connect_scan(self, target: str, port: int) -> str:
        """TCP Connect taraması yapar"""
        try:
            def scan():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                return "open" if result == 0 else "closed"
                
            return await asyncio.get_event_loop().run_in_executor(self.executor, scan)
            
        except Exception as e:
            return "filtered"
            
    async def _udp_scan(self, target: str, port: int) -> str:
        """UDP taraması yapar"""
        try:
            def grab():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                try:
                    if port == 53:
                        # DNS sorgusu gönder (örneğin, example.com için A kaydı)
                        dns_query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                        sock.sendto(dns_query, (target, port))
                        data, _ = sock.recvfrom(1024) # Yanıt bekle
                        return "open" # Yanıt geldiyse açık kabul et
                    else:
                        # Diğer UDP portları için boş veri gönder
                        sock.sendto(b"", (target, port))
                        data, _ = sock.recvfrom(1024)
                        return "open"
                except socket.timeout:
                    # Zaman aşımı, port açık veya filtrelenmiş olabilir
                    return "open|filtered"
                except socket.error as e:
                    # Socket hatası, genellikle port kapalıdır (ICMP hatası)
                    # Belirli ICMP hatalarını kontrol edebiliriz, ama şimdilik genel hata kapalı kabul edilebilir.
                    # Ya da sadece hata durumunda filtered dönelim, GUI bunu daha iyi yorumlar.
                    # Örneğin, Windows'ta Port Unreachable hatası socket.error olarak gelebilir.
                    return "closed" # Hata durumunda kapalı kabul edelim
                finally:
                    sock.close()
                    
            return await asyncio.get_event_loop().run_in_executor(None, grab)
            
        except Exception as e:
            self.logger.error(f"UDP port {port} taraması sırasında hata: {str(e)}")
            return "filtered"
            
    async def tcp_syn_scan(self, target_ip: str, ports: List[int]) -> Dict[int, str]:
        """
        TCP SYN taraması gerçekleştirir.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            
        Returns:
            Dict[int, str]: Açık portlar ve durumları
        """
        open_ports = {}
        
        for port in ports:
            syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(None, lambda: sr1(syn_packet, timeout=1, verbose=False))
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R")
                        send(rst_packet, verbose=False)
                        open_ports[port] = "open"
                        print(f"Port {port} açık")
                
            except Exception as e:
                continue
                
        return open_ports
    
    async def udp_scan(self, target_ip: str, ports: List[int]) -> Dict[int, str]:
        """
        UDP taraması gerçekleştirir.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            
        Returns:
            Dict[int, str]: Açık portlar ve durumları
        """
        open_ports = {}
        
        for port in ports:
            udp_packet = IP(dst=target_ip)/UDP(dport=port)
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(None, lambda: sr1(udp_packet, timeout=1, verbose=False))
                
                if response is None:
                    open_ports[port] = "open|filtered"
                    self.logger.info(f"Port {port} açık veya filtrelenmiş")
                elif response.haslayer(ICMP):
                    if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
                        open_ports[port] = "closed"
                    elif int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1,2,9,10,13]:
                        open_ports[port] = "filtered"
                
            except Exception as e:
                error_msg = f"Port {port} taraması başarısız oldu: {str(e)}"
                handle_error(self.logger, error_msg)
                
        return open_ports
    
    def validate_ports(self, ports):
        """Port numaralarının geçerli olup olmadığını kontrol eder."""
        for port in ports:
            if not (0 <= port <= 65535):
                raise ValueError(f"Geçersiz port numarası: {port}")

    def validate_ip(self, ip):
        """IP adresinin geçerli olup olmadığını kontrol eder."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Geçersiz IP adresi: {ip}")

    async def fin_scan(self, target_ip: str, ports: List[int]) -> Dict[int, str]:
        """
        FIN taraması gerçekleştirir. IDS/IPS sistemlerinden kaçınmak için kullanılır.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            
        Returns:
            Dict[int, str]: Açık portlar ve durumları
        """
        open_ports = {}
        
        for port in ports:
            fin_packet = IP(dst=target_ip)/TCP(dport=port, flags="F")
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(None, lambda: sr1(fin_packet, timeout=1, verbose=False))
                
                if response is None:
                    open_ports[port] = "open|filtered"
                    self.logger.info(f"Port {port} açık veya filtrelenmiş (FIN tarama)")
                elif response.haslayer(ICMP):
                    if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1,2,9,10,13]:
                        open_ports[port] = "filtered"
                
            except Exception as e:
                error_msg = f"Port {port} FIN taraması başarısız oldu: {str(e)}"
                handle_error(self.logger, error_msg)
                
        return open_ports

    async def xmas_scan(self, target_ip: str, ports: List[int]) -> Dict[int, str]:
        """
        XMAS taraması gerçekleştirir. FIN, PSH ve URG flaglerini kullanır.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            
        Returns:
            Dict[int, str]: Açık portlar ve durumları
        """
        open_ports = {}
        
        for port in ports:
            xmas_packet = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(None, lambda: sr1(xmas_packet, timeout=1, verbose=False))
                
                if response is None:
                    open_ports[port] = "open|filtered"
                    self.logger.info(f"Port {port} açık veya filtrelenmiş (XMAS tarama)")
                elif response.haslayer(ICMP):
                    if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1,2,9,10,13]:
                        open_ports[port] = "filtered"
                
            except Exception as e:
                error_msg = f"Port {port} XMAS taraması başarısız oldu: {str(e)}"
                handle_error(self.logger, error_msg)
                
        return open_ports

    async def null_scan(self, target_ip: str, ports: List[int]) -> Dict[int, str]:
        """
        NULL taraması gerçekleştirir. Hiçbir flag kullanmaz.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            
        Returns:
            Dict[int, str]: Açık portlar ve durumları
        """
        open_ports = {}
        
        for port in ports:
            null_packet = IP(dst=target_ip)/TCP(dport=port, flags="")
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(None, lambda: sr1(null_packet, timeout=1, verbose=False))
                
                if response is None:
                    open_ports[port] = "open|filtered"
                    self.logger.info(f"Port {port} açık veya filtrelenmiş (NULL tarama)")
                elif response.haslayer(ICMP):
                    if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1,2,9,10,13]:
                        open_ports[port] = "filtered"
                
            except Exception as e:
                error_msg = f"Port {port} NULL taraması başarısız oldu: {str(e)}"
                handle_error(self.logger, error_msg)
                
        return open_ports

    async def scan_target(self, target_ip: str, ports: List[int], scan_type: str = "tcp") -> Dict:
        """
        Hedef IP'yi belirtilen portlarda tarar.
        
        Args:
            target_ip (str): Hedef IP adresi
            ports (List[int]): Taranacak port listesi
            scan_type (str): Tarama tipi
            
        Returns:
            Dict: Tarama sonuçları
        """
        start_time = time.time()
        results = {}
        
        # Portları gruplara böl
        port_groups = [ports[i:i + self.max_workers] for i in range(0, len(ports), self.max_workers)]
        
        for group in port_groups:
            # Her grup için eşzamanlı tarama
            tasks = [self.scan_port(target_ip, port, scan_type) for port in group]
            group_results = await asyncio.gather(*tasks)
            
            # Sonuçları birleştir
            for result in group_results:
                results.update(result)
                
        end_time = time.time()
        
        return {
            'ip': target_ip,
            'scan_type': scan_type,
            'ports': results,
            'scan_time': end_time - start_time,
            'total_ports': len(ports),
            'open_ports': len([p for p, s in results.items() if s == 'open']),
            'closed_ports': len([p for p, s in results.items() if s == 'closed']),
            'filtered_ports': len([p for p, s in results.items() if s == 'filtered']),
            'error_ports': len([p for p, s in results.items() if s == 'error'])
        }
        
    def __del__(self):
        """ThreadPoolExecutor'ı temizle."""
        self.executor.shutdown(wait=False)

    def scan(self, target, ports, scan_type="TCP", service_detection=False):
        """
        Belirtilen hedef ve portlarda tarama yapar
        """
        results = {
            'target': target,
            'scan_type': scan_type,
            'open_ports': []
        }
        
        total_ports = len(ports)
        scanned_count = 0
        
        for port in ports:
            try:
                if scan_type == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service_info = self._get_service_info(target, port, "tcp") if service_detection else None
                        results['open_ports'].append({
                            'port': port,
                            'service': service_info
                        })
                        print(f"Port {port}: AÇIK (TCP)")
                    sock.close()
                
                elif scan_type == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    try:
                        # UDP portuna boş veri gönder
                        sock.sendto(b"", (target, port))
                        # Yanıt bekle
                        data, addr = sock.recvfrom(1024)
                        service_info = self._get_service_info(target, port, "udp") if service_detection else None
                        results['open_ports'].append({
                            'port': port,
                            'service': service_info
                        })
                        print(f"Port {port}: AÇIK (UDP)")
                    except socket.error:
                        # UDP portu açık olabilir ama yanıt vermiyor olabilir
                        service_info = self._get_service_info(target, port, "udp") if service_detection else None
                        if service_info:
                            results['open_ports'].append({
                                'port': port,
                                'service': service_info
                            })
                            print(f"Port {port}: Açık veya Filtrelenmiş (UDP)")
                    finally:
                        sock.close()
            
            except Exception as e:
                print(f"Port {port} taranırken hata: {str(e)}")
                continue
            
            scanned_count += 1
            progress = (scanned_count / total_ports) * 100
            print(f"\rTarama İlerlemesi: {progress:.1f}% ({scanned_count}/{total_ports})", end="")
        
        print("\nTarama tamamlandı.")
        return results
