import unittest
import asyncio
from src.scanner.port_scanner import PortScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        """Test öncesi hazırlık."""
        self.port_scanner = PortScanner()

    def test_scan_target(self):
        """Asenkron port tarama testi."""
        target = "127.0.0.1"
        tcp_ports = [80, 443]
        udp_ports = [53]

        results = asyncio.run(self.port_scanner.scan_target(target, tcp_ports, udp_ports))
        
        self.assertIsNotNone(results)
        self.assertIn('tcp_ports', results)
        self.assertIn('udp_ports', results)
        self.assertIn('scan_time', results)

if __name__ == '__main__':
    unittest.main() 