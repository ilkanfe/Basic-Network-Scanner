from scapy.all import *
import logging
from typing import Dict, Optional
import platform
import re
from src.utils.logger import setup_logger
from src.utils.error_utils import handle_error
from src.utils.platform_utils import is_windows, get_platform_specific_command

class OSFingerprinter:
    def __init__(self):
        """İşletim sistemi parmak izi çıkarma sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        
    def ttl_analysis(self, target_ip: str) -> Optional[str]:
        """
        TTL değeri analizi ile işletim sistemi tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            
        Returns:
            Optional[str]: Tespit edilen işletim sistemi
        """
        try:
            # ICMP echo request gönder
            ping = IP(dst=target_ip)/ICMP()
            response = sr1(ping, timeout=2, verbose=False)
            
            if response:
                ttl = response.ttl
                
                # TTL değerine göre işletim sistemi tespiti
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"
                    
        except Exception as e:
            error_msg = f"TTL analizi başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            
        return None
    
    def tcp_stack_analysis(self, target_ip: str) -> Dict:
        """
        TCP/IP stack analizi ile işletim sistemi tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            
        Returns:
            Dict: TCP/IP stack özellikleri
        """
        stack_info = {
            'window_size': None,
            'tcp_options': None,
            'ip_id': None,
            'df_flag': None
        }
        
        try:
            # SYN paketi gönder
            syn_packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
            response = sr1(syn_packet, timeout=2, verbose=False)
            
            if response and response.haslayer(TCP):
                # Window size analizi
                stack_info['window_size'] = response[TCP].window
                
                # TCP options analizi
                if TCP in response and response[TCP].options:
                    stack_info['tcp_options'] = [opt[0] for opt in response[TCP].options]
                
                # IP ID analizi
                stack_info['ip_id'] = response[IP].id
                
                # DF flag analizi
                stack_info['df_flag'] = response[IP].flags.DF
                
        except Exception as e:
            error_msg = f"TCP stack analizi başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
            
        return stack_info
    
    def nmap_os_detection(self, target_ip: str) -> Optional[str]:
        """
        Nmap ile işletim sistemi tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            
        Returns:
            Optional[str]: Tespit edilen işletim sistemi
        """
        try:
            import nmap
            nm = nmap.PortScanner()
            # Platforma özel Nmap komutu
            nmap_cmd = get_platform_specific_command('nmap')
            nm.scan(target_ip, arguments=f'{nmap_cmd} -O')
            if target_ip in nm.all_hosts():
                if 'osmatch' in nm[target_ip]:
                    best_match = nm[target_ip]['osmatch'][0]
                    return best_match['name']
        except Exception as e:
            error_msg = f"Nmap OS detection başarısız oldu: {str(e)}"
            handle_error(self.logger, error_msg)
        return None
    
    def fingerprint_os(self, target_ip: str) -> Dict:
        """
        Tüm yöntemleri kullanarak işletim sistemi tespiti yapar.
        
        Args:
            target_ip (str): Hedef IP adresi
            
        Returns:
            Dict: İşletim sistemi tespit sonuçları
        """
        results = {
            'ttl_analysis': self.ttl_analysis(target_ip),
            'tcp_stack': self.tcp_stack_analysis(target_ip),
            'nmap_detection': self.nmap_os_detection(target_ip),
            'final_guess': None
        }
        
        # Sonuçları değerlendir
        if results['nmap_detection']:
            results['final_guess'] = results['nmap_detection']
        elif results['ttl_analysis']:
            results['final_guess'] = results['ttl_analysis']
        else:
            # TCP stack özelliklerine göre tahmin
            tcp_stack = results['tcp_stack']
            if tcp_stack['window_size']:
                if tcp_stack['window_size'] <= 65535:
                    results['final_guess'] = "Linux/Unix"
                else:
                    results['final_guess'] = "Windows"
        
        return results
