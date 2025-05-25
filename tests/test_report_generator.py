import unittest
from src.visualization.report_generator import ReportGenerator
import os
import pytest
import json
import csv

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        """Test öncesi hazırlık."""
        self.report_generator = ReportGenerator()

    def test_generate_report(self):
        """Rapor oluşturma testi."""
        scan_results = {'ip': '127.0.0.1', 'tcp_ports': {80: 'open', 443: 'closed'}, 'udp_ports': {53: 'open'}}
        services = {80: {'name': 'http', 'product': 'nginx', 'version': '1.18.0', 'state': 'open'}}
        os_results = {'ttl_analysis': 'Linux', 'tcp_stack': {'window_size': 65535}, 'nmap_detection': 'Linux', 'final_guess': 'Linux'}

        report_path = self.report_generator.generate_report(scan_results, services, os_results)
        self.assertIsNotNone(report_path)
        self.assertTrue(report_path.endswith('.html'))

        # PDF raporunun oluşturulduğunu kontrol et
        pdf_path = report_path.replace('.html', '.pdf')
        self.assertTrue(os.path.exists(pdf_path))

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
                    80: {
                        'state': 'open',
                        'service': {
                            'name': 'http',
                            'version': '2.4.41'
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
                            'version': '10.0'
                        }
                    }
                }
            }
        ]
    }

def test_save_json(sample_scan_results, tmp_path):
    """JSON rapor kaydetme testi."""
    generator = ReportGenerator(output_dir=str(tmp_path))
    filepath = generator.save_json(sample_scan_results)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filepath)
    assert filepath.endswith('.json')
    
    # JSON içeriğini kontrol et
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        assert data['target'] == sample_scan_results['target']
        assert len(data['hosts']) == len(sample_scan_results['hosts'])

def test_save_csv(sample_scan_results, tmp_path):
    """CSV rapor kaydetme testi."""
    generator = ReportGenerator(output_dir=str(tmp_path))
    filepath = generator.save_csv(sample_scan_results)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filepath)
    assert filepath.endswith('.csv')
    
    # CSV içeriğini kontrol et
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 2  # İki host için iki satır
        assert rows[0]['IP'] == '192.168.1.1'
        assert rows[1]['IP'] == '192.168.1.2'

def test_save_summary(sample_scan_results, tmp_path):
    """Özet rapor kaydetme testi."""
    generator = ReportGenerator(output_dir=str(tmp_path))
    filepath = generator.save_summary(sample_scan_results)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filepath)
    assert filepath.endswith('.txt')
    
    # Özet içeriğini kontrol et
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        assert 'Tarama Hedefi: 192.168.1.0/24' in content
        assert 'Linux: 1 host' in content
        assert 'Windows: 1 host' in content
        assert 'Port 80:' in content
        assert 'Port 445:' in content

def test_save_pdf(sample_scan_results, tmp_path):
    """PDF rapor kaydetme testi."""
    generator = ReportGenerator(output_dir=str(tmp_path))
    filepath = generator.save_pdf(sample_scan_results)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filepath)
    assert filepath.endswith('.pdf')
    
    # PDF dosya boyutunu kontrol et (boş olmadığından emin olmak için)
    assert os.path.getsize(filepath) > 0

if __name__ == '__main__':
    unittest.main() 