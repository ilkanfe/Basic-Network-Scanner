import asyncio
from src.scanner.os_fingerprinter import OSFingerprinter
import logging

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_os_fingerprinting():
    # Test edilecek IP adresleri
    test_ips = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
        '192.168.1.1'  # Yerel ağ gateway'i
    ]
    
    fingerprinter = OSFingerprinter()
    
    for ip in test_ips:
        logger.info(f"\n{ip} için OS Fingerprinting başlatılıyor...")
        try:
            os_info = await fingerprinter.detect_os(ip)
            
            logger.info(f"Sonuçlar ({ip}):")
            logger.info(f"OS Adı: {os_info.get('name', 'Bilinmiyor')}")
            logger.info(f"Güven Skoru: {os_info.get('confidence', 0):.2f}")
            logger.info(f"TTL Analizi: {os_info.get('ttl_analysis', {}).get('os', 'Bilinmiyor')}")
            logger.info(f"TCP Stack Analizi: {os_info.get('stack_analysis', {}).get('behavior', 'Bilinmiyor')}")
            
        except Exception as e:
            logger.error(f"Hata ({ip}): {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_os_fingerprinting()) 