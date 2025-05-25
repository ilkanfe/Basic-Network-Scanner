import argparse
import logging
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.os_fingerprint import OSFingerprinter
from visualization.report_generator import ReportGenerator

def setup_logging():
    """Loglama ayarlarını yapılandırır."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scanner.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Ana uygulama fonksiyonu."""
    # Komut satırı argümanlarını ayarla
    parser = argparse.ArgumentParser(description='Ağ Tarama Aracı')
    parser.add_argument('target', help='Hedef IP adresi veya IP aralığı (CIDR formatında)')
    parser.add_argument('--tcp-ports', help='Taranacak TCP portları (örn: 80,443,8080)')
    parser.add_argument('--udp-ports', help='Taranacak UDP portları (örn: 53,67,68)')
    parser.add_argument('--no-os-detection', action='store_true', help='İşletim sistemi tespitini devre dışı bırak')
    parser.add_argument('--no-service-detection', action='store_true', help='Servis tespitini devre dışı bırak')
    
    args = parser.parse_args()
    
    # Loglama ayarlarını yapılandır
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Port tarayıcıyı başlat
        port_scanner = PortScanner()
        
        # Hedef IP'yi veya IP aralığını tara
        if '/' in args.target:  # CIDR formatında IP aralığı
            logger.info(f"IP aralığı taranıyor: {args.target}")
            active_hosts = port_scanner.scan_ip_range(args.target)
            logger.info(f"Aktif hostlar: {active_hosts}")
            
            # Her aktif host için tarama yap
            for host in active_hosts:
                scan_host(host, args, logger)
        else:  # Tek IP
            scan_host(args.target, args, logger)
            
    except Exception as e:
        logger.error(f"Tarama sırasında hata oluştu: {str(e)}")

def scan_host(host: str, args: argparse.Namespace, logger: logging.Logger):
    """Tek bir host için tarama işlemini gerçekleştirir."""
    try:
        # Port tarayıcıyı başlat
        port_scanner = PortScanner()
        
        # TCP portlarını ayarla
        tcp_ports = None
        if args.tcp_ports:
            tcp_ports = [int(p) for p in args.tcp_ports.split(',')]
        
        # UDP portlarını ayarla
        udp_ports = None
        if args.udp_ports:
            udp_ports = [int(p) for p in args.udp_ports.split(',')]
        
        # Port taraması yap
        logger.info(f"Host taranıyor: {host}")
        scan_results = port_scanner.scan_target(host, tcp_ports, udp_ports)
        
        # Servis tespiti
        services = {}
        if not args.no_service_detection:
            logger.info("Servis tespiti yapılıyor...")
            service_detector = ServiceDetector()
            
            # TCP servisleri
            tcp_services = service_detector.detect_services(host, scan_results['tcp_ports'], 'tcp')
            services.update(tcp_services)
            
            # UDP servisleri
            udp_services = service_detector.detect_services(host, scan_results['udp_ports'], 'udp')
            services.update(udp_services)
        
        # İşletim sistemi tespiti
        os_results = {}
        if not args.no_os_detection:
            logger.info("İşletim sistemi tespiti yapılıyor...")
            os_fingerprinter = OSFingerprinter()
            os_results = os_fingerprinter.fingerprint_os(host)
        
        # Rapor oluştur
        logger.info("Rapor oluşturuluyor...")
        report_generator = ReportGenerator()
        report_path = report_generator.generate_report(scan_results, services, os_results)
        
        logger.info(f"Tarama tamamlandı. Rapor: {report_path}")
        
    except Exception as e:
        logger.error(f"Host tarama hatası ({host}): {str(e)}")

if __name__ == '__main__':
    main() 