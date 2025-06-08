import pytest
import asyncio
from src.scanner.port_scanner import PortScanner, ScanResult
import time

@pytest.fixture
def scanner():
    """Test için PortScanner örneği oluşturur"""
    return PortScanner(timeout=1.0, max_workers=10, connection_pool_size=20, chunk_size=5)

@pytest.mark.asyncio
async def test_connection_pool(scanner):
    """Bağlantı havuzunun düzgün çalıştığını test eder"""
    # Test için localhost'u kullan
    target = "127.0.0.1"
    start_port = 80
    end_port = 85
    
    # İlk tarama
    start_time = time.time()
    results1 = await scanner.scan_ports(target, start_port, end_port, "tcp")
    first_scan_time = time.time() - start_time
    
    # İkinci tarama (önbellekten faydalanmalı)
    start_time = time.time()
    results2 = await scanner.scan_ports(target, start_port, end_port, "tcp")
    second_scan_time = time.time() - start_time
    
    # İkinci tarama daha hızlı olmalı
    assert second_scan_time <= first_scan_time
    assert len(results1) == len(results2)
    
    # Sonuçların doğru formatta olduğunu kontrol et
    for port, result in results1.items():
        assert isinstance(result, ScanResult)
        assert hasattr(result, 'port')
        assert hasattr(result, 'state')
        assert hasattr(result, 'scan_time')

@pytest.mark.asyncio
async def test_port_chunking(scanner):
    """Port gruplarının doğru şekilde oluşturulduğunu test eder"""
    target = "127.0.0.1"
    start_port = 1
    end_port = 20
    
    results = await scanner.scan_ports(target, start_port, end_port, "tcp")
    
    # Tüm portların taranmış olması gerekir
    assert len(results) == end_port - start_port + 1
    
    # Port numaralarının sıralı olması gerekir
    ports = sorted(results.keys())
    assert ports == list(range(start_port, end_port + 1))

@pytest.mark.asyncio
async def test_concurrent_scanning(scanner):
    """Eşzamanlı taramanın düzgün çalıştığını test eder"""
    target = "127.0.0.1"
    start_port = 1
    end_port = 50
    
    start_time = time.time()
    results = await scanner.scan_ports(target, start_port, end_port, "tcp")
    scan_time = time.time() - start_time
    
    # Tarama süresi makul bir sürede tamamlanmalı
    # 50 port için 5 saniyeden az sürmeli
    assert scan_time < 5.0
    
    # Tüm portların taranmış olması gerekir
    assert len(results) == end_port - start_port + 1

@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Hata durumlarının düzgün yönetildiğini test eder"""
    # Geçersiz IP adresi
    with pytest.raises(ValueError):
        await scanner.scan_ports("invalid_ip", 80, 85, "tcp")
    
    # Geçersiz port aralığı
    with pytest.raises(ValueError):
        await scanner.scan_ports("127.0.0.1", 100, 80, "tcp")
    
    # Geçersiz tarama tipi
    with pytest.raises(ValueError):
        await scanner.scan_ports("127.0.0.1", 80, 85, "invalid_type")

@pytest.mark.asyncio
async def test_cleanup(scanner):
    """Kaynakların düzgün temizlendiğini test eder"""
    target = "127.0.0.1"
    start_port = 80
    end_port = 85
    
    # Tarama yap
    await scanner.scan_ports(target, start_port, end_port, "tcp")
    
    # Temizleme işlemini çağır
    await scanner.cleanup()
    
    # Bağlantı havuzunun boş olduğunu kontrol et
    assert len(scanner.connection_pool.pool) == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 