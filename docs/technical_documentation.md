# Teknik Dokümantasyon

## Modül Yapısı

### 1. src/scanner/port_scanner.py
- **PortScanner**: IP aralığı ve port tarama işlemlerini gerçekleştirir.
  - `scan_ip_range(ip_range)`: Belirtilen IP aralığındaki aktif hostları bulur.
  - `tcp_syn_scan(target_ip, ports)`: TCP SYN taraması yapar.
  - `udp_scan(target_ip, ports)`: UDP port taraması yapar.
  - `fin_scan`, `xmas_scan`, `null_scan`: Stealth tarama modları.
  - `scan_target(target_ip, tcp_ports, udp_ports, scan_type)`: Tüm tarama işlemlerini yönetir.

### 2. src/scanner/service_detector.py
- **ServiceDetector**: Açık portlarda çalışan servisleri ve banner bilgilerini tespit eder.
  - `detect_service(target_ip, port, protocol)`: Tek bir portta servis tespiti.
  - `banner_grab(target_ip, port, protocol)`: Banner grabbing ile servis bilgisi alma.
  - `detect_services(target_ip, ports, protocol)`: Birden fazla port için toplu servis tespiti.

### 3. src/scanner/os_fingerprint.py
- **OSFingerprinter**: Hedef sistemin işletim sistemini çeşitli yöntemlerle tespit eder.
  - `ttl_analysis(target_ip)`: TTL değeri ile OS tespiti.
  - `tcp_stack_analysis(target_ip)`: TCP/IP stack analizi ile OS tespiti.
  - `nmap_os_detection(target_ip)`: Nmap ile OS tespiti.
  - `fingerprint_os(target_ip)`: Tüm yöntemleri birleştirerek en iyi tahmini döndürür.

### 4. src/visualization/report_generator.py
- **ReportGenerator**: Tüm sonuçları HTML ve PDF formatında raporlar.
  - `create_port_heatmap(scan_results)`: Port ısı haritası oluşturur.
  - `create_service_pie_chart(services)`: Servis dağılımı grafiği oluşturur.
  - `create_os_detection_bar(os_results)`: OS tespit çubuk grafiği oluşturur.
  - `generate_report(scan_results, services, os_results)`: Kapsamlı HTML ve PDF rapor üretir.

## Yardımcı Modüller
- **src/utils/network_utils.py**: IP ve port doğrulama, zaman damgası üretimi.
- **src/utils/logger.py**: Loglama altyapısı.
- **src/utils/error_utils.py**: Hata yönetimi ve kullanıcıya dost hata mesajları.
- **src/utils/platform_utils.py**: Platforma özel komut ve ayarlar.

## Akış Diyagramı (Sözlü)
1. Kullanıcı hedef IP veya IP aralığını girer.
2. PortScanner ile aktif hostlar ve açık portlar tespit edilir.
3. ServiceDetector ile açık portlardaki servisler ve banner bilgileri alınır.
4. OSFingerprinter ile hedefin işletim sistemi tespit edilir.
5. Tüm sonuçlar ReportGenerator ile görsel ve metinsel rapora dönüştürülür.

## Geliştirici Notları
- Tüm ana fonksiyonlarda docstring açıklamaları mevcuttur.
- Asenkron fonksiyonlar için `asyncio` kullanılmıştır.
- Testler `tests/` klasöründe yer alır ve unittest ile çalıştırılır. 