import pytest
import asyncio
from src.scanner.service_detector import ServiceDetector

@pytest.fixture
def service_detector():
    return ServiceDetector(timeout=2.0)

@pytest.mark.asyncio
async def test_ssl_security(service_detector):
    """SSL/TLS güvenlik kontrolünü test eder"""
    # Test için localhost üzerinde çalışan bir HTTPS servisi olmalı
    target_ip = "127.0.0.1"
    port = 443
    
    service_info = {
        'name': 'https',
        'product': 'HTTPS',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_ssh_security(service_detector):
    """SSH güvenlik kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 22
    
    service_info = {
        'name': 'ssh',
        'product': 'SSH',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_http_security(service_detector):
    """HTTP güvenlik kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 80
    
    service_info = {
        'name': 'http',
        'product': 'HTTP',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_ftp_security(service_detector):
    """FTP güvenlik kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 21
    
    service_info = {
        'name': 'ftp',
        'product': 'FTP',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_smtp_security(service_detector):
    """SMTP güvenlik kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 25
    
    service_info = {
        'name': 'smtp',
        'product': 'SMTP',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_rdp_security(service_detector):
    """RDP güvenlik kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 3389
    
    service_info = {
        'name': 'rdp',
        'product': 'RDP',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert isinstance(security_info['vulnerabilities'], list)
    assert isinstance(security_info['security_score'], int)
    assert isinstance(security_info['recommendations'], list)

@pytest.mark.asyncio
async def test_invalid_service(service_detector):
    """Geçersiz servis kontrolünü test eder"""
    target_ip = "127.0.0.1"
    port = 12345
    
    service_info = {
        'name': 'unknown',
        'product': 'Unknown',
        'version': 'unknown',
        'state': 'open'
    }
    
    security_info = await service_detector.check_security(target_ip, port, service_info)
    
    assert isinstance(security_info, dict)
    assert 'vulnerabilities' in security_info
    assert 'security_score' in security_info
    assert 'recommendations' in security_info
    assert security_info['security_score'] == 100  # Bilinmeyen servisler için varsayılan puan
    assert len(security_info['vulnerabilities']) == 0  # Bilinmeyen servisler için güvenlik açığı olmamalı 

@pytest.mark.asyncio
async def test_udp_dns_service(service_detector):
    """UDP 53 (DNS) servis tespitini test eder"""
    target_ip = "127.0.0.1"
    port = 53
    service_info = await service_detector.detect_service(target_ip, port, protocol='udp')
    assert isinstance(service_info, dict)
    assert service_info['name'] == 'domain'
    assert service_info['product'] == 'DNS'

@pytest.mark.asyncio
async def test_udp_snmp_service(service_detector):
    """UDP 161 (SNMP) servis tespitini test eder"""
    target_ip = "127.0.0.1"
    port = 161
    service_info = await service_detector.detect_service(target_ip, port, protocol='udp')
    assert isinstance(service_info, dict)
    assert service_info['name'] == 'snmp'
    assert service_info['product'] == 'SNMP'

@pytest.mark.asyncio
async def test_udp_ntp_service(service_detector):
    """UDP 123 (NTP) servis tespitini test eder"""
    target_ip = "127.0.0.1"
    port = 123
    service_info = await service_detector.detect_service(target_ip, port, protocol='udp')
    assert isinstance(service_info, dict)
    assert service_info['name'] == 'ntp'
    assert service_info['product'] == 'NTP' 