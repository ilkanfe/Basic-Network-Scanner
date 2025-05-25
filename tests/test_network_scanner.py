import pytest
import asyncio
from src.scanner.network_scanner import NetworkScanner

@pytest.mark.asyncio
async def test_single_host_scan():
    """Tek host tarama testi."""
    scanner = NetworkScanner(timeout=2.0, max_workers=5)
    
    # Localhost'u tara
    result = await scanner.scan_network('127.0.0.1')
    
    # Temel kontroller
    assert isinstance(result, dict)
    assert 'scan_time' in result
    assert 'target' in result
    assert 'hosts' in result
    assert len(result['hosts']) > 0
    
    # Host bilgilerini kontrol et
    host = result['hosts'][0]
    assert host['ip'] == '127.0.0.1'
    assert 'os_info' in host
    assert 'ports' in host
    
    # OS bilgilerini kontrol et
    os_info = host['os_info']
    assert 'name' in os_info
    assert 'confidence' in os_info
    
    # Port bilgilerini kontrol et
    assert isinstance(host['ports'], dict)

@pytest.mark.asyncio
async def test_network_scan():
    """Ağ tarama testi."""
    scanner = NetworkScanner(timeout=2.0, max_workers=5)
    
    # Küçük bir ağı tara
    result = await scanner.scan_network('127.0.0.0/30')
    
    # Temel kontroller
    assert isinstance(result, dict)
    assert 'scan_time' in result
    assert 'target' in result
    assert 'hosts' in result
    
    # En az bir host bulunmalı
    assert len(result['hosts']) > 0

@pytest.mark.asyncio
async def test_custom_ports():
    """Özel port tarama testi."""
    scanner = NetworkScanner(timeout=2.0, max_workers=5)
    
    # Sadece HTTP ve HTTPS portlarını tara
    ports = {80, 443}
    result = await scanner.scan_network('127.0.0.1', ports=ports)
    
    # Port kontrolleri
    host = result['hosts'][0]
    assert set(host['ports'].keys()).issubset(ports)

@pytest.mark.asyncio
async def test_invalid_target():
    """Geçersiz hedef testi."""
    scanner = NetworkScanner(timeout=2.0, max_workers=5)
    
    # Geçersiz IP adresi
    result = await scanner.scan_network('256.256.256.256')
    
    # Hata durumunu kontrol et
    assert 'error' in result
    assert len(result['hosts']) == 0 