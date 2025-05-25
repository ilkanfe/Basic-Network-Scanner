# Proje Sunum Özeti

## Proje Adı
**Basic Network Scanner**

## Amaç
Ağ üzerindeki cihazları, açık portları, çalışan servisleri ve işletim sistemlerini tespit eden, hızlı ve görsel raporlar sunan bir ağ keşif aracı geliştirmek.

## Temel Özellikler
- TCP/UDP port tarama
- Stealth tarama modları (SYN, FIN, XMAS, NULL)
- Servis tespiti ve banner grabbing
- İşletim sistemi tespiti (TTL, TCP/IP stack, Nmap)
- HTML ve PDF formatında görsel raporlar
- Windows & Linux desteği

## Sistem Mimarisi
1. **Scanner Engine:** IP aralığı ve port tarama, OS fingerprinting
2. **Service Detector:** Servis tespiti ve banner grabbing
3. **Visualization Layer:** Sonuçların grafik ve rapor olarak sunulması

## Kullanım Akışı
1. Kullanıcı hedef IP aralığını girer
2. Aktif hostlar ve açık portlar tespit edilir
3. Servis ve işletim sistemi analizi yapılır
4. Sonuçlar görsel ve metinsel rapor olarak sunulur

## Test ve Sonuçlar
- Ortalama tarama süresi: 0.1 saniye (localhost)
- Doğruluk oranı: %100 (localhost)
- Stealth tarama modları başarıyla çalışıyor
- Raporlar otomatik olarak `reports/` klasöründe oluşuyor

## Ekran Görüntüleri
- (Buraya HTML/PDF raporlarından örnek ekran görüntüleri ekleyebilirsiniz)

## Ekip
- Mustafa İlkan DEMİR
- Tolga TOK
- Hatice BİÇEN

## Soru & Cevap
Sorularınız için: [uoilkan@gmail.com] 