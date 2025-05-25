import pytest
import time
from src.scanner.port_scanner import PortScanner

class TestPerformance:
    @pytest.fixture(autouse=True)
    def setup(self):
        """Test öncesi hazırlık."""
        self.port_scanner = PortScanner()

    @pytest.mark.asyncio
    async def test_large_port_list(self):
        """Büyük port listesi ile tarama testi."""
        target = "127.0.0.1"
        large_port_list = list(range(1, 101))  # 100 port
        start_time = time.time()
        await self.port_scanner.scan_target(target, tcp_ports=large_port_list)
        end_time = time.time()
        scan_time = end_time - start_time
        assert scan_time < 30, f"Tarama süresi çok uzun: {scan_time} saniye"

    @pytest.mark.asyncio
    async def test_large_ip_range(self):
        """Büyük IP aralığı ile tarama testi."""
        ip_range = "192.168.1.0/28"  # 16 IP adresi
        start_time = time.time()
        active_hosts = self.port_scanner.scan_ip_range(ip_range)
        end_time = time.time()
        scan_time = end_time - start_time
        assert scan_time < 60, f"Tarama süresi çok uzun: {scan_time} saniye" 