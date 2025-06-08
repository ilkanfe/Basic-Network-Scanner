import pytest
import asyncio
from src.scanner.os_fingerprinter import OSFingerprinter

@pytest.fixture
def os_fingerprinter():
    return OSFingerprinter()

@pytest.mark.asyncio
async def test_fingerprint_known_os(os_fingerprinter):
    # Bu testi çalıştırmadan önce, ağınızda açık bir porta sahip bilinen bir işletim sistemi (örn. router, Linux VM, Windows PC) bulun.
    # Hedef IP ve açık portu güncelleyin.
    target_ip = "192.168.1.1"  # Kendi ağınızdaki bir hedefin IP adresini girin
    open_port = 80  # Hedefteki açık olduğu bilinen bir port

    print(f"\n{target_ip} adresinin işletim sistemi tahmin ediliyor...")
    os_name = os_fingerprinter.fingerprint_os(target_ip, open_port)
    print(f"Tahmin edilen İşletim Sistemi: {os_name}")

    # Testin başarılı sayılması için beklenen bir çıktıya göre assertion yapın.
    # Bu, test ettiğiniz sisteme bağlı olarak değişecektir.
    # Örneğin, 'Windows' veya 'Linux' gibi bir değeri kontrol edebilirsiniz.
    assert isinstance(os_name, str)
    assert os_name != "Bilinmiyor (yanıt yok veya SYN-ACK değil)"
    assert os_name != "Bilinmiyor (belirli özellikler eşleşmedi)"

@pytest.mark.asyncio
async def test_fingerprint_unknown_host(os_fingerprinter):
    # Ulaşılabilir olmayan bir IP adresi için test
    non_existent_ip = "192.0.2.1"  # RFC 5737 - TEST-NET-1 (Dokümantasyon ve örnekler için ayrılmış)
    open_port = 80

    print(f"\n{non_existent_ip} adresinin işletim sistemi tahmin ediliyor...")
    os_name = os_fingerprinter.fingerprint_os(non_existent_ip, open_port)
    print(f"Tahmin edilen İşletim Sistemi: {os_name}")

    # Ulaşılabilir olmayan bir IP için beklenen çıktı
    assert os_name == "Bilinmiyor (yanıt yok veya SYN-ACK değil)"

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