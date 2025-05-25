import pytest
from src.utils.data_analyzer import DataAnalyzer

@pytest.fixture
def sample_scan_results():
    """Örnek tarama sonuçları."""
    return {
        'scan_time': 1234567890.0,
        'target': '192.168.1.0/24',
        'hosts': [
            {
                'ip': '192.168.1.1',
                'os_info': {
                    'name': 'Linux',
                    'confidence': 0.85
                },
                'ports': {
                    22: {
                        'state': 'open',
                        'service': {
                            'name': 'ssh',
                            'version': 'OpenSSH 8.2'
                        }
                    },
                    80: {
                        'state': 'open',
                        'service': {
                            'name': 'http',
                            'version': 'Apache 2.4.41'
                        }
                    }
                }
            },
            {
                'ip': '192.168.1.2',
                'os_info': {
                    'name': 'Windows',
                    'confidence': 0.92
                },
                'ports': {
                    445: {
                        'state': 'open',
                        'service': {
                            'name': 'microsoft-ds',
                            'version': 'Windows 10'
                        }
                    },
                    3389: {
                        'state': 'open',
                        'service': {
                            'name': 'ms-wbt-server',
                            'version': '2012'
                        }
                    }
                }
            }
        ]
    }

def test_analyze_scan_results(sample_scan_results):
    """Genel analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    
    assert 'summary' in analysis
    assert 'os_distribution' in analysis
    assert 'port_analysis' in analysis
    assert 'service_analysis' in analysis
    assert 'security_analysis' in analysis

def test_summary_analysis(sample_scan_results):
    """Özet analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    summary = analysis['summary']
    
    assert summary['total_hosts'] == 2
    assert summary['active_hosts'] == 2
    assert summary['total_ports'] == 4
    assert summary['open_ports'] == 4

def test_os_distribution_analysis(sample_scan_results):
    """İşletim sistemi dağılımı analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    os_dist = analysis['os_distribution']
    
    assert 'Linux' in os_dist
    assert 'Windows' in os_dist
    assert os_dist['Linux']['count'] == 1
    assert os_dist['Windows']['count'] == 1
    assert 0.8 <= os_dist['Linux']['confidence_avg'] <= 0.9
    assert 0.9 <= os_dist['Windows']['confidence_avg'] <= 1.0

def test_port_analysis(sample_scan_results):
    """Port analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    port_analysis = analysis['port_analysis']
    
    assert 22 in port_analysis
    assert 80 in port_analysis
    assert 445 in port_analysis
    assert 3389 in port_analysis
    
    assert port_analysis[22]['open'] == 1
    assert port_analysis[80]['open'] == 1
    assert 'ssh' in port_analysis[22]['services']
    assert 'http' in port_analysis[80]['services']

def test_service_analysis(sample_scan_results):
    """Servis analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    service_analysis = analysis['service_analysis']
    
    assert 'ssh' in service_analysis
    assert 'http' in service_analysis
    assert 'microsoft-ds' in service_analysis
    
    assert service_analysis['ssh']['count'] == 1
    assert service_analysis['http']['count'] == 1
    assert 22 in service_analysis['ssh']['ports']
    assert 80 in service_analysis['http']['ports']

def test_security_analysis(sample_scan_results):
    """Güvenlik analiz testi."""
    analyzer = DataAnalyzer()
    analysis = analyzer.analyze_scan_results(sample_scan_results)
    security_analysis = analysis['security_analysis']
    
    assert security_analysis['total_issues'] > 0
    assert security_analysis['hosts_with_issues'] > 0
    assert 'issues_by_severity' in security_analysis
    assert 'detailed_issues' in security_analysis
    
    # Eski sürüm kontrolü
    old_version_found = False
    for host in security_analysis['detailed_issues']:
        for issue in host['issues']:
            if issue['type'] == 'outdated_service' and '2012' in issue['version']:
                old_version_found = True
                break
    assert old_version_found 