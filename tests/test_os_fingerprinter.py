import pytest
import asyncio
from src.scanner.os_fingerprinter import OSFingerprinter

@pytest.mark.asyncio
async def test_os_detection():
    """OS tespiti testi."""
    fingerprinter = OSFingerprinter(timeout=2.0)
    
    # Test için localhost kullanıyoruz
    result = await fingerprinter.detect_os('127.0.0.1')
    
    # Temel kontroller
    assert isinstance(result, dict)
    assert 'name' in result
    assert 'confidence' in result
    assert 'ttl_analysis' in result
    assert 'stack_analysis' in result
    
    # Güven skoru kontrolü
    assert 0 <= result['confidence'] <= 1
    
    # TTL analizi kontrolü
    assert isinstance(result['ttl_analysis'], dict)
    assert 'os' in result['ttl_analysis']
    assert 'ttl' in result['ttl_analysis']
    
    # TCP stack analizi kontrolü
    assert isinstance(result['stack_analysis'], dict)
    assert 'behavior' in result['stack_analysis']
    assert 'details' in result['stack_analysis']

@pytest.mark.asyncio
async def test_invalid_ip():
    """Geçersiz IP testi."""
    fingerprinter = OSFingerprinter(timeout=2.0)
    
    # Geçersiz IP adresi
    result = await fingerprinter.detect_os('256.256.256.256')
    
    # Hata durumunda beklenen sonuçlar
    assert result['name'] == 'unknown'
    assert result['confidence'] == 0
    assert result['ttl_analysis']['os'] == 'Unknown'
    assert result['stack_analysis']['behavior'] == 'unknown' 