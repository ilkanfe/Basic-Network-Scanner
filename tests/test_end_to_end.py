import pytest
import asyncio
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.scanner.os_fingerprint import OSFingerprinter
from src.visualization.report_generator import ReportGenerator
import os

class TestEndToEnd:
    @pytest.fixture(autouse=True)
    def setup(self):
        """Test öncesi hazırlık."""
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.os_fingerprinter = OSFingerprinter()
        self.report_generator = ReportGenerator()

    @pytest.mark.asyncio
    async def test_full_scan(self):
        """End-to-end tarama testi."""
        target = "127.0.0.1"
        tcp_ports = [80, 443]
        udp_ports = [53]

        # Port taraması
        scan_results = await self.port_scanner.scan_target(target, tcp_ports, udp_ports)
        assert scan_results is not None
        assert 'tcp_ports' in scan_results
        assert 'udp_ports' in scan_results

        # Servis tespiti
        services = {}
        for port, state in scan_results['tcp_ports'].items():
            if state == 'open':
                service_info = self.service_detector.detect_service(target, port)
                services[port] = service_info

        # OS tespiti
        os_results = self.os_fingerprinter.fingerprint_os(target)
        assert os_results is not None
        assert 'final_guess' in os_results

        # Rapor oluşturma
        report_path = self.report_generator.generate_report(scan_results, services, os_results)
        assert report_path is not None
        assert report_path.endswith('.html')

        # PDF raporunun oluşturulduğunu kontrol et
        pdf_path = report_path.replace('.html', '.pdf')
        assert os.path.exists(pdf_path) 