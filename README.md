# Ağ Tarayıcı

Bu proje, ağ üzerindeki cihazları, açık portları ve çalışan servisleri tespit etmek için geliştirilmiş bir araçtır.

## Özellikler

- IP adresi tarama
- Port tarama (TCP Connect ve SYN)
- Servis tespiti
- Cihaz tespiti (MAC adresi ve cihaz tipi)
- Kullanıcı dostu GUI arayüzü

## Kurulum

1. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

2. Uygulamayı başlatın:
```bash
python main.py
```

## Kullanım

1. Hedef IP aralığını girin (örn: 192.168.1.0/24 veya 192.168.1.1-192.168.1.10)
2. Port aralığını girin (örn: 1-1000 veya 80,443,8080)
3. Tarama tipini seçin (TCP Connect veya SYN)
4. İsterseniz "Servis Tespiti" seçeneğini işaretleyin
5. "Taramayı Başlat" butonuna tıklayın

## Güvenlik Notu

Bu aracı sadece kendi ağınızda veya izin verilen sistemlerde kullanın. İzinsiz tarama yapmak yasalara aykırı olabilir.

## Lisans

MIT 