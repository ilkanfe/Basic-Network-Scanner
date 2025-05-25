# Kullanıcı Kılavuzu

## 1. Kurulum

1. Python 3.8+ yüklü olmalı.
2. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. Nmap ve Scapy'nin sistemde kurulu olduğundan emin olun:
   - Windows: https://nmap.org/download.html
   - Linux: `sudo apt install nmap`
4. Proje dizinine girin:
   ```bash
   cd Basic-Network-Scanner
   ```

## 2. Temel Kullanım

### Komut Satırından Test
```bash
python -m unittest discover tests
```

### Python ile Kullanım
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

## 3. Parametreler ve Seçenekler
- **scan_target** fonksiyonunda `scan_type` parametresi ile farklı tarama modları seçebilirsiniz:
  - `syn`: Standart SYN taraması
  - `fin`: Stealth FIN taraması
  - `xmas`: Stealth XMAS taraması
  - `null`: Stealth NULL taraması
- Port listesi ve UDP taraması için parametreleri özelleştirebilirsiniz.

## 4. Raporlar
- Tüm raporlar `reports/` klasöründe oluşur.
- HTML ve PDF formatında raporlar otomatik olarak kaydedilir.
- Raporlar; port ısı haritası, servis dağılımı, işletim sistemi tespiti ve güvenlik önerileri içerir.

## 5. Sıkça Sorulan Sorular
- **Raporlar nerede oluşur?**
  - `reports/` klasöründe.
- **Hatalarla karşılaşırsam ne yapmalıyım?**
  - Hata mesajını ve logları kontrol edin. Bağımlılıkların kurulu olduğundan emin olun.
- **Kullanıcı arayüzü var mı?**
  - Şu an için sadece komut satırı ve Python API üzerinden kullanılabilir.

## 6. Destek ve İletişim
Sorularınız için ekip üyelerine veya [email@example.com] adresine ulaşabilirsiniz. 