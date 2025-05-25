import pytest
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector

class TestErrorHandling:
    @pytest.fixture(autouse=True)
    def setup(self):
        """Test öncesi hazırlık."""
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()

    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        """Geçersiz IP adresi ile tarama testi."""
        invalid_ip = "256.256.256.256"
        with pytest.raises(ValueError):
            await self.port_scanner.scan_target(invalid_ip)

    @pytest.mark.asyncio
    async def test_invalid_port(self):
        """Geçersiz port numarası ile tarama testi."""
        target = "127.0.0.1"
        invalid_ports = [70000]  # Geçersiz port numarası
        with pytest.raises(ValueError):
            await self.port_scanner.scan_target(target, tcp_ports=invalid_ports) 