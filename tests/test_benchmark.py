import unittest
import asyncio
import time
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.scanner.os_fingerprint import OSFingerprinter
import logging

class TestBenchmark(unittest.TestCase):
    def setUp(self):
        """Test öncesi hazırlık."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        self.port_scanner = PortScanner(timeout=1.0, max_workers=50)
        self.service_detector = ServiceDetector(timeout=2.0, max_workers=20)
        self.os_fingerprinter = OSFingerprinter()
        
    async def measure_scan_time(self, scan_func, *args, **kwargs):
        """Tarama süresini ölçer."""
        start_time = time.time()
        result = await scan_func(*args, **kwargs)
        end_time = time.time()
        return result, end_time - start_time
        
    async def test_scan_speed(self):
        """Tarama hızı testi."""
        target = "127.0.0.1"
        ports = list(range(1, 1025))  # İlk 1024 port
        
        # TCP SYN tarama
        result, scan_time = await self.measure_scan_time(
            self.port_scanner.scan_target,
            target,
            ports,
            "syn"
        )
        
        self.logger.info(f"TCP SYN tarama süresi: {scan_time:.2f} saniye")
        self.logger.info(f"Taranan port sayısı: {len(ports)}")
        self.logger.info(f"Ortalama port başına süre: {scan_time/len(ports)*1000:.2f} ms")
        
        self.assertLess(scan_time, len(ports) * 0.1)  # Port başına 100ms'den az olmalı
        
    async def test_accuracy(self):
        """Tarama doğruluğu testi."""
        target = "127.0.0.1"
        known_ports = {80: "open", 443: "open", 22: "open"}  # Bilinen portlar
        
        result = await self.port_scanner.scan_target(target, list(known_ports.keys()))
        
        for port, expected_state in known_ports.items():
            if port in result['ports']:
                self.logger.info(f"Port {port}: Beklenen={expected_state}, Bulunan={result['ports'][port]}")
                self.assertIn(result['ports'][port], [expected_state, "filtered"])
                
    async def test_stealth_scan_performance(self):
        """Stealth tarama performans testi."""
        target = "127.0.0.1"
        ports = list(range(1, 1025))
        
        scan_types = ["fin", "xmas", "null"]
        for scan_type in scan_types:
            result, scan_time = await self.measure_scan_time(
                self.port_scanner.scan_target,
                target,
                ports,
                scan_type
            )
            
            self.logger.info(f"{scan_type.upper()} tarama süresi: {scan_time:.2f} saniye")
            self.assertLess(scan_time, len(ports) * 0.1)
            
    async def test_service_detection_performance(self):
        """Servis tespit performans testi."""
        target = "127.0.0.1"
        ports = {80: "open", 443: "open", 22: "open"}
        
        result, detection_time = await self.measure_scan_time(
            self.service_detector.detect_services,
            target,
            ports
        )
        
        self.logger.info(f"Servis tespit süresi: {detection_time:.2f} saniye")
        self.logger.info(f"Tespit edilen servis sayısı: {len(result)}")
        self.assertLess(detection_time, len(ports) * 2.0)  # Port başına 2 saniyeden az olmalı
        
    async def test_os_detection_performance(self):
        """İşletim sistemi tespit performans testi."""
        target = "127.0.0.1"
        
        start_time = time.time()
        result = self.os_fingerprinter.fingerprint_os(target)
        detection_time = time.time() - start_time
        
        self.logger.info(f"İşletim sistemi tespit süresi: {detection_time:.2f} saniye")
        self.assertLess(detection_time, 5.0)  # 5 saniyeden az olmalı
        
def run_async_test(test_func):
    """Asenkron test fonksiyonunu çalıştırır."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(test_func())

if __name__ == '__main__':
    # Testleri sırayla çalıştır
    test = TestBenchmark()
    test.setUp()
    
    print("\nTarama Hızı Testi:")
    run_async_test(test.test_scan_speed)
    
    print("\nDoğruluk Testi:")
    run_async_test(test.test_accuracy)
    
    print("\nStealth Tarama Performans Testi:")
    run_async_test(test.test_stealth_scan_performance)
    
    print("\nServis Tespit Performans Testi:")
    run_async_test(test.test_service_detection_performance)
    
    print("\nİşletim Sistemi Tespit Performans Testi:")
    run_async_test(test.test_os_detection_performance) 