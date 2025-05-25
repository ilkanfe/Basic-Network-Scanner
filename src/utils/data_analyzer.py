from typing import Dict, List, Set, Optional
from collections import defaultdict
from src.utils.logger import setup_logger

class DataAnalyzer:
    def __init__(self):
        """Veri analiz sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        
    def analyze_scan_results(self, scan_results: Dict) -> Dict:
        """
        Tarama sonuçlarını analiz eder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            
        Returns:
            Dict: Analiz sonuçları
        """
        try:
            analysis = {
                'summary': self._generate_summary(scan_results),
                'os_distribution': self._analyze_os_distribution(scan_results),
                'port_analysis': self._analyze_ports(scan_results),
                'service_analysis': self._analyze_services(scan_results),
                'security_analysis': self._analyze_security(scan_results)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Veri analizi hatası: {str(e)}")
            return {}
            
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Genel özet oluşturur."""
        hosts = scan_results.get('hosts', [])
        
        return {
            'total_hosts': len(hosts),
            'active_hosts': len([h for h in hosts if h.get('ports')]),
            'total_ports': sum(len(h.get('ports', {})) for h in hosts),
            'open_ports': sum(
                sum(1 for p in h.get('ports', {}).values() if p.get('state') == 'open')
                for h in hosts
            ),
            'scan_time': scan_results.get('scan_time'),
            'target': scan_results.get('target')
        }
        
    def _analyze_os_distribution(self, scan_results: Dict) -> Dict:
        """İşletim sistemi dağılımını analiz eder."""
        os_stats = defaultdict(lambda: {'count': 0, 'confidence_avg': 0.0})
        
        for host in scan_results.get('hosts', []):
            os_info = host.get('os_info', {})
            os_name = os_info.get('name', 'Unknown')
            confidence = os_info.get('confidence', 0.0)
            
            os_stats[os_name]['count'] += 1
            os_stats[os_name]['confidence_avg'] = (
                (os_stats[os_name]['confidence_avg'] * (os_stats[os_name]['count'] - 1) + confidence) /
                os_stats[os_name]['count']
            )
            
        return dict(os_stats)
        
    def _analyze_ports(self, scan_results: Dict) -> Dict:
        """Port analizi yapar."""
        port_stats = defaultdict(lambda: {
            'open': 0,
            'closed': 0,
            'filtered': 0,
            'services': set()
        })
        
        for host in scan_results.get('hosts', []):
            for port, info in host.get('ports', {}).items():
                state = info.get('state', 'unknown')
                service = info.get('service', {}).get('name', 'unknown')
                
                port_stats[port][state] += 1
                port_stats[port]['services'].add(service)
                
        # Set'leri listeye çevir
        for stats in port_stats.values():
            stats['services'] = list(stats['services'])
            
        return dict(port_stats)
        
    def _analyze_services(self, scan_results: Dict) -> Dict:
        """Servis analizi yapar."""
        service_stats = defaultdict(lambda: {
            'count': 0,
            'versions': set(),
            'ports': set()
        })
        
        for host in scan_results.get('hosts', []):
            for port, info in host.get('ports', {}).items():
                if info.get('state') == 'open':
                    service = info.get('service', {})
                    service_name = service.get('name', 'unknown')
                    version = service.get('version', 'unknown')
                    
                    service_stats[service_name]['count'] += 1
                    service_stats[service_name]['versions'].add(version)
                    service_stats[service_name]['ports'].add(port)
                    
        # Set'leri listeye çevir
        for stats in service_stats.values():
            stats['versions'] = list(stats['versions'])
            stats['ports'] = list(stats['ports'])
            
        return dict(service_stats)
        
    def _analyze_security(self, scan_results: Dict) -> Dict:
        """Güvenlik analizi yapar."""
        security_issues = []
        common_vulnerable_ports = {21, 22, 23, 25, 445, 3389}  # Örnek portlar
        
        for host in scan_results.get('hosts', []):
            host_issues = []
            ip = host.get('ip', 'Unknown')
            
            # Açık portları kontrol et
            for port, info in host.get('ports', {}).items():
                if info.get('state') == 'open':
                    # Bilinen güvenlik açığı olan portları kontrol et
                    if port in common_vulnerable_ports:
                        service = info.get('service', {}).get('name', 'unknown')
                        host_issues.append({
                            'type': 'vulnerable_port',
                            'port': port,
                            'service': service,
                            'severity': 'high',
                            'description': f'Port {port} ({service}) açık ve potansiyel güvenlik riski oluşturabilir'
                        })
                        
                    # Eski sürüm servisleri kontrol et
                    version = info.get('service', {}).get('version', '')
                    if version and any(year in version for year in ['2010', '2011', '2012', '2013', '2014', '2015']):
                        host_issues.append({
                            'type': 'outdated_service',
                            'port': port,
                            'service': info.get('service', {}).get('name', 'unknown'),
                            'version': version,
                            'severity': 'medium',
                            'description': f'Eski sürüm servis tespit edildi: {version}'
                        })
                        
            if host_issues:
                security_issues.append({
                    'ip': ip,
                    'issues': host_issues
                })
                
        return {
            'total_issues': sum(len(host['issues']) for host in security_issues),
            'hosts_with_issues': len(security_issues),
            'issues_by_severity': {
                'high': sum(1 for host in security_issues for issue in host['issues'] if issue['severity'] == 'high'),
                'medium': sum(1 for host in security_issues for issue in host['issues'] if issue['severity'] == 'medium'),
                'low': sum(1 for host in security_issues for issue in host['issues'] if issue['severity'] == 'low')
            },
            'detailed_issues': security_issues
        } 