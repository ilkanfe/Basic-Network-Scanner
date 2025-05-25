# Basic Network Scanner

## Proje Tanımı ve Amacı
Basic Network Scanner, ağ üzerindeki cihazları, açık portları, çalışan servisleri ve işletim sistemlerini tespit etmek için geliştirilmiş hafif ve güçlü bir ağ keşif aracıdır. IT yöneticileri ve siber güvenlik uzmanları için hızlı ve görsel raporlar sunar.

## Özellikler
- TCP/UDP port tarama
- Stealth (gizli) tarama modları (SYN, FIN, XMAS, NULL)
- Servis tespiti ve banner grabbing
- İşletim sistemi tespiti (TTL, TCP/IP stack, Nmap)
- HTML ve PDF formatında görsel raporlar
- Platform desteği: Windows & Linux
- Kolay kurulum ve kullanım

## Kurulum
1. Gerekli kütüphaneleri yükleyin:
```bash
pip install -r requirements.txt
```
2. Nmap ve Scapy'nin sistemde kurulu olduğundan emin olun:
   - Windows için: https://nmap.org/download.html
   - Linux için: `sudo apt install nmap`
3. Proje dizinine gidin:
```bash
cd Basic-Network-Scanner
```

## Kullanım
Python ile temel kullanım örneği:
```python
from src.scanner.port_scanner import PortScanner
from src.scanner.service_detector import ServiceDetector
from src.scanner.os_fingerprint import OSFingerprinter
from src.visualization.report_generator import ReportGenerator
import asyncio

scanner = PortScanner()
results = asyncio.run(scanner.scan_target('192.168.1.1', scan_type='syn'))

service_detector = ServiceDetector()
services = service_detector.detect_services('192.168.1.1', results['tcp_ports'])

os_fingerprinter = OSFingerprinter()
os_results = os_fingerprinter.fingerprint_os('192.168.1.1')

reporter = ReportGenerator()
report_path = reporter.generate_report(results, services, os_results)
print(f'Rapor oluşturuldu: {report_path}')
```

### Komut Satırından Testler
```bash
python -m unittest discover tests
```

## Örnek Çıktılar
- HTML ve PDF raporları `reports/` klasöründe oluşur.
- Raporlar; port ısı haritası, servis dağılımı, işletim sistemi tespiti ve güvenlik önerileri içerir.

## Modüller Hakkında Kısa Bilgi
- **port_scanner.py**: IP aralığı ve port tarama işlemlerini gerçekleştirir.
- **service_detector.py**: Açık portlarda çalışan servisleri ve banner bilgilerini tespit eder.
- **os_fingerprint.py**: Hedef sistemin işletim sistemini çeşitli yöntemlerle tespit eder.
- **report_generator.py**: Tüm sonuçları HTML ve PDF formatında raporlar.

## Sıkça Sorulan Sorular
- **Raporlar nerede oluşur?**
  - Tüm raporlar `reports/` klasöründe saklanır.
- **Hatalarla karşılaşırsam ne yapmalıyım?**
  - Hata mesajını ve logları kontrol edin. Bağımlılıkların kurulu olduğundan emin olun.
- **Kullanıcı arayüzü var mı?**
  - Şu an için sadece komut satırı ve Python API üzerinden kullanılabilir.

## Katkı ve Lisans
Katkı yapmak isteyenler için pull request gönderebilir veya issue açabilirsiniz. Proje MIT lisansı ile lisanslanmıştır.

## Ekip ve İletişim
- Mustafa İlkan DEMİR
- Tolga TOK
- Hatice BİÇEN
Sorularınız için: [email@example.com] 