import pytest
import os
from src.visualization.scan_visualizer import ScanVisualizer

@pytest.fixture
def sample_scan_results():
    """Örnek tarama sonuçları."""
    return [
        {
            'ip': '192.168.1.1',
            'name': 'Linux',
            'confidence': 0.85,
            'ports': {
                80: {'state': 'open', 'service': {'name': 'http'}},
                443: {'state': 'open', 'service': {'name': 'https'}}
            }
        },
        {
            'ip': '192.168.1.2',
            'name': 'Windows',
            'confidence': 0.92,
            'ports': {
                445: {'state': 'open', 'service': {'name': 'microsoft-ds'}},
                3389: {'state': 'open', 'service': {'name': 'rdp'}}
            }
        }
    ]

def test_os_distribution_pie(sample_scan_results, tmp_path):
    """OS dağılım pasta grafiği testi."""
    visualizer = ScanVisualizer()
    output_path = tmp_path / "os_distribution.png"
    
    # Grafiği oluştur
    visualizer.create_os_distribution_pie(sample_scan_results, str(output_path))
    
    # Dosyanın oluşturulduğunu kontrol et
    assert output_path.exists()
    assert output_path.stat().st_size > 0

def test_port_heatmap(sample_scan_results, tmp_path):
    """Port ısı haritası testi."""
    visualizer = ScanVisualizer()
    output_path = tmp_path / "port_heatmap.html"
    
    # Grafiği oluştur
    visualizer.create_port_heatmap(sample_scan_results, str(output_path))
    
    # Dosyanın oluşturulduğunu kontrol et
    assert output_path.exists()
    assert output_path.stat().st_size > 0

def test_confidence_bar(sample_scan_results, tmp_path):
    """Güven skoru çubuk grafiği testi."""
    visualizer = ScanVisualizer()
    output_path = tmp_path / "confidence_bar.html"
    
    # Grafiği oluştur
    visualizer.create_confidence_bar(sample_scan_results, str(output_path))
    
    # Dosyanın oluşturulduğunu kontrol et
    assert output_path.exists()
    assert output_path.stat().st_size > 0

def test_interactive_dashboard(sample_scan_results, tmp_path):
    """İnteraktif dashboard testi."""
    visualizer = ScanVisualizer()
    output_path = tmp_path / "dashboard.html"
    
    # Dashboard'ı oluştur
    visualizer.create_interactive_dashboard(sample_scan_results, str(output_path))
    
    # Dosyanın oluşturulduğunu kontrol et
    assert output_path.exists()
    assert output_path.stat().st_size > 0 