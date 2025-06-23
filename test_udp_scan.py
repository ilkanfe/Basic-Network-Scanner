import asyncio
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector

async def test_udp_scan():
    # Port tarayıcı ve servis tespitçi nesnelerini oluştur
    port_scanner = PortScanner(timeout=2.0)
    service_detector = ServiceDetector(timeout=2.0)
    
    # Test edilecek hedef IP (örnek olarak localhost)
    target = "127.0.0.1"
    
    # Yaygın UDP portları
    common_udp_ports = [53, 123, 161, 67, 68, 69]
    
    print(f"\nUDP Port Taraması Başlatılıyor...")
    print(f"Hedef: {target}")
    print(f"Taranacak Portlar: {common_udp_ports}")
    print("-" * 50)
    
    # Her port için ayrı tarama yap
    for port in common_udp_ports:
        print(f"\nPort {port} taranıyor...")
        port_results = await port_scanner.scan_ports(target, port, port, scan_type="udp")
        
        if port in port_results and port_results[port] == "open":
            print(f"Port {port}: AÇIK")
            
            # Servis tespiti yap
            service_info = await service_detector.detect_service(target, port, protocol='udp')
            print(f"Tespit Edilen Servis:")
            print(f"  Servis: {service_info['name']}")
            print(f"  Ürün: {service_info['product']}")
            print(f"  Versiyon: {service_info['version']}")
            if service_info['banner']:
                print(f"  Banner: {service_info['banner']}")
        else:
            print(f"Port {port}: KAPALI veya FİLTRELENMİŞ")
        
        print("-" * 30)

if __name__ == "__main__":
    asyncio.run(test_udp_scan()) 