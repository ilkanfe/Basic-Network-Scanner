from typing import Dict, List, Optional, Set
from src.utils.logger import setup_logger

class ResultFilter:
    def __init__(self):
        """Sonuç filtreleme sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        
    def filter_results(self, scan_results: Dict, 
                      host_filter: Optional[str] = None,
                      port_filter: Optional[Set[int]] = None,
                      service_filter: Optional[Set[str]] = None,
                      state_filter: Optional[Set[str]] = None) -> Dict:
        """
        Tarama sonuçlarını filtreler.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            host_filter (Optional[str]): IP adresi veya host adı filtresi
            port_filter (Optional[Set[int]]): Port numaraları filtresi
            service_filter (Optional[Set[str]]): Servis isimleri filtresi
            state_filter (Optional[Set[str]]): Port durumları filtresi
            
        Returns:
            Dict: Filtrelenmiş tarama sonuçları
        """
        try:
            filtered_results = scan_results.copy()
            filtered_hosts = []
            
            for host in scan_results.get('hosts', []):
                # Host filtresi
                if host_filter and host_filter not in host.get('ip', ''):
                    continue
                    
                filtered_host = host.copy()
                filtered_ports = {}
                
                # Port filtreleme
                for port, info in host.get('ports', {}).items():
                    # Port numarası filtresi
                    if port_filter and port not in port_filter:
                        continue
                        
                    # Servis filtresi
                    if service_filter and info.get('service', {}).get('name') not in service_filter:
                        continue
                        
                    # Durum filtresi
                    if state_filter and info.get('state') not in state_filter:
                        continue
                        
                    filtered_ports[port] = info
                    
                # Filtrelenmiş portları ekle
                filtered_host['ports'] = filtered_ports
                filtered_hosts.append(filtered_host)
                
            # Filtrelenmiş hostları ekle
            filtered_results['hosts'] = filtered_hosts
            
            # İstatistikleri güncelle
            filtered_results['stats'] = {
                'total_hosts': len(filtered_hosts),
                'active_hosts': len([h for h in filtered_hosts if h.get('ports')]),
                'total_ports': sum(len(h.get('ports', {})) for h in filtered_hosts),
                'open_ports': sum(len([p for p, i in h.get('ports', {}).items() 
                                     if i.get('state') == 'open']) 
                                for h in filtered_hosts)
            }
            
            return filtered_results
            
        except Exception as e:
            self.logger.error(f"Sonuç filtreleme hatası: {str(e)}")
            return scan_results
            
    def get_unique_services(self, scan_results: Dict) -> Set[str]:
        """Benzersiz servis isimlerini döndürür."""
        services = set()
        for host in scan_results.get('hosts', []):
            for port_info in host.get('ports', {}).values():
                service_name = port_info.get('service', {}).get('name')
                if service_name:
                    services.add(service_name)
        return services
        
    def get_unique_states(self, scan_results: Dict) -> Set[str]:
        """Benzersiz port durumlarını döndürür."""
        states = set()
        for host in scan_results.get('hosts', []):
            for port_info in host.get('ports', {}).values():
                state = port_info.get('state')
                if state:
                    states.add(state)
        return states 