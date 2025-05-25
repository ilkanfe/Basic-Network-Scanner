import unittest
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.scanner.os_fingerprint import OSFingerprinter
import logging

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        """Test öncesi hazırlık."""
        logging.basicConfig(level=logging.INFO)
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.os_fingerprinter = OSFingerprinter()
        
    def test_port_scanner(self):
        """Port tarayıcı testi."""
        # Localhost üzerinde test
        target = "127.0.0.1"
        results = self.port_scanner.scan_target(target)
        
        self.assertIsNotNone(results)
        self.assertIn('tcp_ports', results)
        self.assertIn('udp_ports', results)
        self.assertIn('scan_time', results)
        
    def test_service_detector(self):
        """Servis tespit testi."""
        # Localhost üzerinde test
        target = "127.0.0.1"
        port = 80  # HTTP portu
        
        service_info = self.service_detector.detect_service(target, port)
        
        self.assertIsNotNone(service_info)
        self.assertIn('name', service_info)
        self.assertIn('product', service_info)
        self.assertIn('version', service_info)
        self.assertIn('state', service_info)
        
    def test_os_fingerprinter(self):
        """İşletim sistemi tespit testi."""
        # Localhost üzerinde test
        target = "127.0.0.1"
        results = self.os_fingerprinter.fingerprint_os(target)
        
        self.assertIsNotNone(results)
        self.assertIn('ttl_analysis', results)
        self.assertIn('tcp_stack', results)
        self.assertIn('nmap_detection', results)
        self.assertIn('final_guess', results)

    def test_stealth_scans(self):
        """Stealth tarama testleri."""
        # Localhost üzerinde test
        target = "127.0.0.1"
        
        # FIN tarama testi
        fin_results = self.port_scanner.scan_target(target, scan_type="fin")
        self.assertIsNotNone(fin_results)
        self.assertIn('tcp_ports', fin_results)
        self.assertEqual(fin_results['scan_type'], "fin")
        
        # XMAS tarama testi
        xmas_results = self.port_scanner.scan_target(target, scan_type="xmas")
        self.assertIsNotNone(xmas_results)
        self.assertIn('tcp_ports', xmas_results)
        self.assertEqual(xmas_results['scan_type'], "xmas")
        
        # NULL tarama testi
        null_results = self.port_scanner.scan_target(target, scan_type="null")
        self.assertIsNotNone(null_results)
        self.assertIn('tcp_ports', null_results)
        self.assertEqual(null_results['scan_type'], "null")
        
        # Geçersiz tarama tipi testi
        with self.assertRaises(ValueError):
            self.port_scanner.scan_target(target, scan_type="invalid")

if __name__ == '__main__':
    unittest.main() 