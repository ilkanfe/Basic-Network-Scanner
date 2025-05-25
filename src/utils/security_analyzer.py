from typing import Dict, List, Set
from src.utils.logger import setup_logger

class SecurityAnalyzer:
    def __init__(self):
        """Güvenlik analiz sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        
        # Bilinen güvenlik açığı olan servisler ve versiyonlar
        self.vulnerable_services = {
            'ftp': {'versions': ['2.0', '2.1'], 'risk': 'high'},
            'ssh': {'versions': ['1.0', '1.1'], 'risk': 'high'},
            'telnet': {'versions': ['*'], 'risk': 'high'},
            'smtp': {'versions': ['2.0', '2.1'], 'risk': 'medium'},
            'http': {'versions': ['1.0', '1.1'], 'risk': 'medium'},
            'https': {'versions': ['1.0', '1.1'], 'risk': 'high'}
        }
        
        # Varsayılan portlar ve risk seviyeleri
        self.default_ports = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            443: 'https',
            3306: 'mysql',
            3389: 'rdp'
        }
        
    def analyze_security(self, scan_results: Dict) -> Dict:
        """
        Tarama sonuçlarını güvenlik açısından analiz eder.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            
        Returns:
            Dict: Güvenlik analiz sonuçları
        """
        try:
            security_issues = []
            hosts_with_issues = set()
            
            for host in scan_results.get('hosts', []):
                host_issues = []
                
                for port, info in host.get('ports', {}).items():
                    if info.get('state') != 'open':
                        continue
                        
                    service_info = info.get('service', {})
                    service_name = service_info.get('name', '').lower()
                    service_version = service_info.get('version', '')
                    
                    # Varsayılan port kontrolü
                    if port in self.default_ports:
                        host_issues.append({
                            'type': 'default_port',
                            'severity': 'medium',
                            'description': f'Port {port} varsayılan {self.default_ports[port]} portu',
                            'port': port,
                            'service': service_name
                        })
                    
                    # Güvenlik açığı olan servis kontrolü
                    if service_name in self.vulnerable_services:
                        vuln_info = self.vulnerable_services[service_name]
                        if service_version in vuln_info['versions'] or '*' in vuln_info['versions']:
                            host_issues.append({
                                'type': 'vulnerable_service',
                                'severity': vuln_info['risk'],
                                'description': f'Bilinen güvenlik açığı olan {service_name} versiyonu ({service_version})',
                                'port': port,
                                'service': service_name,
                                'version': service_version
                            })
                    
                    # Açık port uyarısı
                    if port not in self.default_ports:
                        host_issues.append({
                            'type': 'open_port',
                            'severity': 'low',
                            'description': f'Beklenmeyen açık port: {port}',
                            'port': port,
                            'service': service_name
                        })
                
                if host_issues:
                    hosts_with_issues.add(host.get('ip'))
                    security_issues.append({
                        'ip': host.get('ip'),
                        'issues': host_issues
                    })
            
            # Güvenlik skoru hesapla
            total_issues = len(security_issues)
            high_risk = sum(1 for host in security_issues 
                          for issue in host['issues'] 
                          if issue['severity'] == 'high')
            medium_risk = sum(1 for host in security_issues 
                            for issue in host['issues'] 
                            if issue['severity'] == 'medium')
            
            security_score = 100 - (high_risk * 20 + medium_risk * 10 + total_issues * 5)
            security_score = max(0, min(100, security_score))
            
            return {
                'total_issues': total_issues,
                'hosts_with_issues': len(hosts_with_issues),
                'security_score': security_score,
                'high_risk_issues': high_risk,
                'medium_risk_issues': medium_risk,
                'detailed_issues': security_issues
            }
            
        except Exception as e:
            self.logger.error(f"Güvenlik analizi hatası: {str(e)}")
            return {
                'total_issues': 0,
                'hosts_with_issues': 0,
                'security_score': 100,
                'high_risk_issues': 0,
                'medium_risk_issues': 0,
                'detailed_issues': []
            } 