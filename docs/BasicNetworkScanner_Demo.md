# Basic Network Scanner - Demo Versiyonu

## Demo Özellikleri

### 1. Temel Port Tarama
- TCP port tarama (1-1024 arası portlar)
- Basit SYN tarama
- Açık portların listelenmesi

### 2. Servis Tespiti
- Temel banner grabbing
- Yaygın servislerin tespiti (HTTP, FTP, SSH, Telnet)

### 3. Basit Raporlama
- HTML formatında temel rapor
- Açık portların listesi
- Tespit edilen servisler

## Demo Kullanımı

### Kurulum
```bash
# Gerekli kütüphanelerin kurulumu
pip install -r requirements.txt

# Nmap kurulumu (Windows için)
# https://nmap.org/download.html adresinden indirip kurun
```

### Çalıştırma
```bash
# Temel tarama
python src/main.py --target 192.168.1.1

# Belirli port aralığı ile tarama
python src/main.py --target 192.168.1.1 --ports 80,443,8080

# Servis tespiti ile tarama
python src/main.py --target 192.168.1.1 --service-detect
```

## Demo Sınırlamaları

### Henüz Eklenmemiş Özellikler
- UDP port tarama
- Gelişmiş stealth modları (FIN, XMAS, NULL)
- İşletim sistemi tespiti
- PDF raporlama
- Paralel tarama
- Web arayüzü

### Performans Sınırlamaları
- Tek seferde en fazla 1024 port taranabilir
- Servis tespiti sadece yaygın portlarda yapılır
- Raporlar sadece HTML formatında oluşturulur

## Örnek Çıktı

```bash
$ python src/main.py --target 192.168.1.1 --service-detect

[+] Tarama başlatılıyor: 192.168.1.1
[+] Açık portlar tespit edildi:
    - Port 80: HTTP (Apache/2.4.41)
    - Port 443: HTTPS
    - Port 22: SSH (OpenSSH 8.2p1)
[+] Rapor oluşturuldu: reports/scan_192.168.1.1_20250526.html
```

## Demo Hedefleri
- Temel port tarama işlevselliğini göstermek
- Servis tespiti yeteneklerini sergilemek
- Raporlama sisteminin işleyişini göstermek

---

*Demo Versiyonu - Mayıs 2025*  
*Not: Bu demo versiyonu, projenin tam özelliklerinin bir alt kümesidir.* 