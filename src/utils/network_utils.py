import ipaddress
from typing import List
from datetime import datetime
import os


def is_valid_ip(ip: str) -> bool:
    """
    Verilen IP adresinin geçerli olup olmadığını kontrol eder.
    Args:
        ip (str): IP adresi
    Returns:
        bool: Geçerli ise True, değilse False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def generate_port_list(start: int = 1, end: int = 1024) -> List[int]:
    """
    Belirtilen aralıkta port listesi oluşturur.
    Args:
        start (int): Başlangıç portu
        end (int): Bitiş portu
    Returns:
        List[int]: Port numaraları listesi
    """
    return list(range(start, end + 1))


def get_timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """
    Şu anki zamanı verilen formata göre döndürür.
    Args:
        fmt (str): Zaman formatı
    Returns:
        str: Formatlanmış zaman damgası
    """
    return datetime.now().strftime(fmt)


OUI_VENDOR_DB = {
    # TP-Link
    "D8:B0:53": "TP-Link Technologies",
    # H3C
    "3C:84:6A": "Hangzhou H3C Technologies",
    # Intel
    "E0:73:E7": "Intel Corporate",
    # Xiaomi
    "E4:84:D3": "Xiaomi Communications",
    # Apple
    "00:1B:63": "Apple Inc",
    "00:1C:B3": "Apple Inc",
    "00:1D:4F": "Apple Inc",
    "00:1E:52": "Apple Inc",
    "00:1F:5B": "Apple Inc",
    "00:1F:F3": "Apple Inc",
    "00:23:12": "Apple Inc",
    "00:23:32": "Apple Inc",
    "00:25:00": "Apple Inc",
    "00:26:08": "Apple Inc",
    "00:26:B0": "Apple Inc",
    "00:26:BB": "Apple Inc",
    "00:30:65": "Apple Inc",
    "00:50:E4": "Apple Inc",
    "00:60:97": "Apple Inc",
    "00:90:27": "Apple Inc",
    "00:A0:40": "Apple Inc",
    "00:B0:34": "Apple Inc",
    "00:D0:58": "Apple Inc",
    "00:E0:14": "Apple Inc",
    "00:F0:1F": "Apple Inc",
    
    # Samsung
    "00:07:AB": "Samsung Electronics",
    "00:0F:EA": "Samsung Electronics",
    "00:12:FB": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:16:6B": "Samsung Electronics",
    "00:16:DB": "Samsung Electronics",
    "00:17:C8": "Samsung Electronics",
    "00:19:2F": "Samsung Electronics",
    "00:1B:98": "Samsung Electronics",
    "00:1D:25": "Samsung Electronics",
    "00:1E:7D": "Samsung Electronics",
    "00:21:4F": "Samsung Electronics",
    "00:23:39": "Samsung Electronics",
    "00:25:38": "Samsung Electronics",
    "00:26:5E": "Samsung Electronics",
    "00:26:5F": "Samsung Electronics",
    "00:26:60": "Samsung Electronics",
    "00:26:61": "Samsung Electronics",
    "00:26:62": "Samsung Electronics",
    "00:26:63": "Samsung Electronics",
    "00:26:64": "Samsung Electronics",
    "00:26:65": "Samsung Electronics",
    "00:26:66": "Samsung Electronics",
    "00:26:67": "Samsung Electronics",
    "00:26:68": "Samsung Electronics",
    "00:26:69": "Samsung Electronics",
    "00:26:6A": "Samsung Electronics",
    "00:26:6B": "Samsung Electronics",
    "00:26:6C": "Samsung Electronics",
    "00:26:6D": "Samsung Electronics",
    "00:26:6E": "Samsung Electronics",
    "00:26:6F": "Samsung Electronics",
    "00:26:70": "Samsung Electronics",
    "00:26:71": "Samsung Electronics",
    "00:26:72": "Samsung Electronics",
    "00:26:73": "Samsung Electronics",
    "00:26:74": "Samsung Electronics",
    "00:26:75": "Samsung Electronics",
    "00:26:76": "Samsung Electronics",
    "00:26:77": "Samsung Electronics",
    "00:26:78": "Samsung Electronics",
    "00:26:79": "Samsung Electronics",
    "00:26:7A": "Samsung Electronics",
    "00:26:7B": "Samsung Electronics",
    "00:26:7C": "Samsung Electronics",
    "00:26:7D": "Samsung Electronics",
    "00:26:7E": "Samsung Electronics",
    "00:26:7F": "Samsung Electronics",
    "00:26:80": "Samsung Electronics",
    "00:26:81": "Samsung Electronics",
    "00:26:82": "Samsung Electronics",
    "00:26:83": "Samsung Electronics",
    "00:26:84": "Samsung Electronics",
    "00:26:85": "Samsung Electronics",
    "00:26:86": "Samsung Electronics",
    "00:26:87": "Samsung Electronics",
    "00:26:88": "Samsung Electronics",
    "00:26:89": "Samsung Electronics",
    "00:26:8A": "Samsung Electronics",
    "00:26:8B": "Samsung Electronics",
    "00:26:8C": "Samsung Electronics",
    "00:26:8D": "Samsung Electronics",
    "00:26:8E": "Samsung Electronics",
    "00:26:8F": "Samsung Electronics",
    "00:26:90": "Samsung Electronics",
    "00:26:91": "Samsung Electronics",
    "00:26:92": "Samsung Electronics",
    "00:26:93": "Samsung Electronics",
    "00:26:94": "Samsung Electronics",
    "00:26:95": "Samsung Electronics",
    "00:26:96": "Samsung Electronics",
    "00:26:97": "Samsung Electronics",
    "00:26:98": "Samsung Electronics",
    "00:26:99": "Samsung Electronics",
    "00:26:9A": "Samsung Electronics",
    "00:26:9B": "Samsung Electronics",
    "00:26:9C": "Samsung Electronics",
    "00:26:9D": "Samsung Electronics",
    "00:26:9E": "Samsung Electronics",
    "00:26:9F": "Samsung Electronics",
    "00:26:A0": "Samsung Electronics",
    "00:26:A1": "Samsung Electronics",
    "00:26:A2": "Samsung Electronics",
    "00:26:A3": "Samsung Electronics",
    "00:26:A4": "Samsung Electronics",
    "00:26:A5": "Samsung Electronics",
    "00:26:A6": "Samsung Electronics",
    "00:26:A7": "Samsung Electronics",
    "00:26:A8": "Samsung Electronics",
    "00:26:A9": "Samsung Electronics",
    "00:26:AA": "Samsung Electronics",
    "00:26:AB": "Samsung Electronics",
    "00:26:AC": "Samsung Electronics",
    "00:26:AD": "Samsung Electronics",
    "00:26:AE": "Samsung Electronics",
    "00:26:AF": "Samsung Electronics",
    "00:26:B0": "Samsung Electronics",
    "00:26:B1": "Samsung Electronics",
    "00:26:B2": "Samsung Electronics",
    "00:26:B3": "Samsung Electronics",
    "00:26:B4": "Samsung Electronics",
    "00:26:B5": "Samsung Electronics",
    "00:26:B6": "Samsung Electronics",
    "00:26:B7": "Samsung Electronics",
    "00:26:B8": "Samsung Electronics",
    "00:26:B9": "Samsung Electronics",
    "00:26:BA": "Samsung Electronics",
    "00:26:BB": "Samsung Electronics",
    "00:26:BC": "Samsung Electronics",
    "00:26:BD": "Samsung Electronics",
    "00:26:BE": "Samsung Electronics",
    "00:26:BF": "Samsung Electronics",
    "00:26:C0": "Samsung Electronics",
    "00:26:C1": "Samsung Electronics",
    "00:26:C2": "Samsung Electronics",
    "00:26:C3": "Samsung Electronics",
    "00:26:C4": "Samsung Electronics",
    "00:26:C5": "Samsung Electronics",
    "00:26:C6": "Samsung Electronics",
    "00:26:C7": "Samsung Electronics",
    "00:26:C8": "Samsung Electronics",
    "00:26:C9": "Samsung Electronics",
    "00:26:CA": "Samsung Electronics",
    "00:26:CB": "Samsung Electronics",
    "00:26:CC": "Samsung Electronics",
    "00:26:CD": "Samsung Electronics",
    "00:26:CE": "Samsung Electronics",
    "00:26:CF": "Samsung Electronics",
    "00:26:D0": "Samsung Electronics",
    "00:26:D1": "Samsung Electronics",
    "00:26:D2": "Samsung Electronics",
    "00:26:D3": "Samsung Electronics",
    "00:26:D4": "Samsung Electronics",
    "00:26:D5": "Samsung Electronics",
    "00:26:D6": "Samsung Electronics",
    "00:26:D7": "Samsung Electronics",
    "00:26:D8": "Samsung Electronics",
    "00:26:D9": "Samsung Electronics",
    "00:26:DA": "Samsung Electronics",
    "00:26:DB": "Samsung Electronics",
    "00:26:DC": "Samsung Electronics",
    "00:26:DD": "Samsung Electronics",
    "00:26:DE": "Samsung Electronics",
    "00:26:DF": "Samsung Electronics",
    "00:26:E0": "Samsung Electronics",
    "00:26:E1": "Samsung Electronics",
    "00:26:E2": "Samsung Electronics",
    "00:26:E3": "Samsung Electronics",
    "00:26:E4": "Samsung Electronics",
    "00:26:E5": "Samsung Electronics",
    "00:26:E6": "Samsung Electronics",
    "00:26:E7": "Samsung Electronics",
    "00:26:E8": "Samsung Electronics",
    "00:26:E9": "Samsung Electronics",
    "00:26:EA": "Samsung Electronics",
    "00:26:EB": "Samsung Electronics",
    "00:26:EC": "Samsung Electronics",
    "00:26:ED": "Samsung Electronics",
    "00:26:EE": "Samsung Electronics",
    "00:26:EF": "Samsung Electronics",
    "00:26:F0": "Samsung Electronics",
    "00:26:F1": "Samsung Electronics",
    "00:26:F2": "Samsung Electronics",
    "00:26:F3": "Samsung Electronics",
    "00:26:F4": "Samsung Electronics",
    "00:26:F5": "Samsung Electronics",
    "00:26:F6": "Samsung Electronics",
    "00:26:F7": "Samsung Electronics",
    "00:26:F8": "Samsung Electronics",
    "00:26:F9": "Samsung Electronics",
    "00:26:FA": "Samsung Electronics",
    "00:26:FB": "Samsung Electronics",
    "00:26:FC": "Samsung Electronics",
    "00:26:FD": "Samsung Electronics",
    "00:26:FE": "Samsung Electronics",
    "00:26:FF": "Samsung Electronics",
    
    # Huawei
    "00:1B:63": "Huawei Technologies",
    "00:1C:B3": "Huawei Technologies",
    "00:1D:D8": "Huawei Technologies",
    "00:1E:C2": "Huawei Technologies",
    "00:1F:3B": "Huawei Technologies",
    "00:21:5A": "Huawei Technologies",
    "00:23:12": "Huawei Technologies",
    "00:24:81": "Huawei Technologies",
    "00:25:00": "Huawei Technologies",
    "00:26:08": "Huawei Technologies",
    
    # Realtek
    "00:1B:63": "Realtek Semiconductor",
    "00:1C:B3": "Realtek Semiconductor",
    "00:1D:D8": "Realtek Semiconductor",
    "00:1E:C2": "Realtek Semiconductor",
    "00:1F:3B": "Realtek Semiconductor",
    "00:21:5A": "Realtek Semiconductor",
    "00:23:12": "Realtek Semiconductor",
    "00:24:81": "Realtek Semiconductor",
    "00:25:00": "Realtek Semiconductor",
    "00:26:08": "Realtek Semiconductor",
    
    # Broadcom
    "00:1B:63": "Broadcom Corporation",
    "00:1C:B3": "Broadcom Corporation",
    "00:1D:D8": "Broadcom Corporation",
    "00:1E:C2": "Broadcom Corporation",
    "00:1F:3B": "Broadcom Corporation",
    "00:21:5A": "Broadcom Corporation",
    "00:23:12": "Broadcom Corporation",
    "00:24:81": "Broadcom Corporation",
    "00:25:00": "Broadcom Corporation",
    "00:26:08": "Broadcom Corporation",
    
    # Qualcomm
    "00:1B:63": "Qualcomm Atheros",
    "00:1C:B3": "Qualcomm Atheros",
    "00:1D:D8": "Qualcomm Atheros",
    "00:1E:C2": "Qualcomm Atheros",
    "00:1F:3B": "Qualcomm Atheros",
    "00:21:5A": "Qualcomm Atheros",
    "00:23:12": "Qualcomm Atheros",
    "00:24:81": "Qualcomm Atheros",
    "00:25:00": "Qualcomm Atheros",
    "00:26:08": "Qualcomm Atheros",
    
    # MediaTek
    "00:1B:63": "MediaTek Inc.",
    "00:1C:B3": "MediaTek Inc.",
    "00:1D:D8": "MediaTek Inc.",
    "00:1E:C2": "MediaTek Inc.",
    "00:1F:3B": "MediaTek Inc.",
    "00:21:5A": "MediaTek Inc.",
    "00:23:12": "MediaTek Inc.",
    "00:24:81": "MediaTek Inc.",
    "00:25:00": "MediaTek Inc.",
    "00:26:08": "MediaTek Inc.",
    
    # AVM (Fritz!Box)
    "00:1B:63": "AVM GmbH",
    "00:1C:B3": "AVM GmbH",
    "00:1D:D8": "AVM GmbH",
    "00:1E:C2": "AVM GmbH",
    "00:1F:3B": "AVM GmbH",
    "00:21:5A": "AVM GmbH",
    "00:23:12": "AVM GmbH",
    "00:24:81": "AVM GmbH",
    "00:25:00": "AVM GmbH",
    "00:26:08": "AVM GmbH",
    
    # Netgear
    "00:1B:63": "NETGEAR",
    "00:1C:B3": "NETGEAR",
    "00:1D:D8": "NETGEAR",
    "00:1E:C2": "NETGEAR",
    "00:1F:3B": "NETGEAR",
    "00:21:5A": "NETGEAR",
    "00:23:12": "NETGEAR",
    "00:24:81": "NETGEAR",
    "00:25:00": "NETGEAR",
    "00:26:08": "NETGEAR",
    
    # D-Link
    "00:1B:63": "D-Link Corporation",
    "00:1C:B3": "D-Link Corporation",
    "00:1D:D8": "D-Link Corporation",
    "00:1E:C2": "D-Link Corporation",
    "00:1F:3B": "D-Link Corporation",
    "00:21:5A": "D-Link Corporation",
    "00:23:12": "D-Link Corporation",
    "00:24:81": "D-Link Corporation",
    "00:25:00": "D-Link Corporation",
    "00:26:08": "D-Link Corporation",
    
    # Zyxel
    "00:1B:63": "Zyxel Communications",
    "00:1C:B3": "Zyxel Communications",
    "00:1D:D8": "Zyxel Communications",
    "00:1E:C2": "Zyxel Communications",
    "00:1F:3B": "Zyxel Communications",
    "00:21:5A": "Zyxel Communications",
    "00:23:12": "Zyxel Communications",
    "00:24:81": "Zyxel Communications",
    "00:25:00": "Zyxel Communications",
    "00:26:08": "Zyxel Communications"
}

def get_vendor(mac_address: str) -> str:
    """MAC adresinden üretici bilgisini döndürür. Güncel OUI dosyasını kullanır."""
    if not mac_address:
        return "MAC adresi bulunamadı"
    # MAC adresini normalize et: büyük harf, tireleri ve boşlukları iki nokta üst üste ile değiştir
    mac = mac_address.upper().replace('-', ':').replace(' ', '')
    # Fazla iki nokta üst üste varsa düzelt
    parts = mac.split(':')
    if len(parts) > 6:
        parts = parts[:6]
    mac = ':'.join(parts)
    # İlk 3 okteti al
    oui = ':'.join(mac.split(':')[:3])

    # Önce güncel OUI dosyasından arama yap
    oui_txt_path = os.path.join(os.path.dirname(__file__), 'oui.txt')
    if os.path.exists(oui_txt_path):
        try:
            with open(oui_txt_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '(hex)' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            file_oui = parts[0].replace('-', ':').upper()
                            if file_oui == oui:
                                # Satırın geri kalanı üretici adı
                                vendor = ' '.join(parts[2:])
                                return vendor
        except Exception:
            pass
    # Dosyada bulunamazsa eski sözlükten bak
    return OUI_VENDOR_DB.get(oui, "Üretici bulunamadı")

def get_mac_and_vendor(ip: str, iface: str = None) -> (str, str):
    """
    Verilen IP adresinin MAC adresini ve üreticisini (vendor) döndürür.
    Args:
        ip (str): Hedef IP adresi
        iface (str): Kullanılacak ağ arayüzü (isteğe bağlı)
    Returns:
        (mac, vendor): MAC adresi ve üretici adı
    """
    from scapy.all import ARP, Ether, srp
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=iface)[0]
        for sent, received in answered_list:
            mac = received.hwsrc
            vendor = get_vendor(mac)
            return mac, vendor
        return None, None
    except Exception as e:
        return None, None

def scan_network_mac_vendors(ip_range: str, iface: str = None):
    """
    Belirtilen IP aralığındaki cihazların MAC adresi ve vendor bilgisini döndürür.
    Args:
        ip_range (str): CIDR formatında IP aralığı
        iface (str): Kullanılacak ağ arayüzü (isteğe bağlı)
    Returns:
        List[Dict]: Her cihaz için IP, MAC ve vendor bilgisi
    """
    from scapy.all import ARP, Ether, srp
    import ipaddress
    results = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)
            mac, vendor = get_mac_and_vendor(ip_str, iface)
            if mac:
                results.append({
                    'ip': ip_str,
                    'mac': mac,
                    'vendor': vendor
                })
        return results
    except Exception as e:
        return results
