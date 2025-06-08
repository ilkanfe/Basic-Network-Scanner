import ipaddress
from typing import List
from datetime import datetime


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
    # Intel
    "E0:73:E7": "Intel Corporate",
    "00:1B:63": "Intel Corporate",
    "00:1F:3B": "Intel Corporate",
    "00:25:00": "Intel Corporate",
    "00:26:08": "Intel Corporate",
    "00:27:0E": "Intel Corporate",
    "00:1C:B3": "Intel Corporate",
    "00:1D:D8": "Intel Corporate",
    "00:1E:C2": "Intel Corporate",
    "00:1F:3B": "Intel Corporate",
    
    # Apple
    "00:1B:63": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "00:26:B0": "Apple, Inc.",
    "00:27:0E": "Apple, Inc.",
    "00:1C:B3": "Apple, Inc.",
    "00:1D:D8": "Apple, Inc.",
    "00:1E:C2": "Apple, Inc.",
    "00:1F:3B": "Apple, Inc.",
    "00:1A:2B": "Apple, Inc.",
    
    # Dell
    "00:1B:63": "Dell Inc.",
    "00:1C:B3": "Dell Inc.",
    "00:1D:D8": "Dell Inc.",
    "00:1E:C2": "Dell Inc.",
    "00:1F:3B": "Dell Inc.",
    "00:21:5A": "Dell Inc.",
    "00:23:12": "Dell Inc.",
    "00:24:81": "Dell Inc.",
    "00:25:00": "Dell Inc.",
    "00:26:08": "Dell Inc.",
    
    # HP/Hewlett Packard
    "00:1B:63": "Hewlett Packard",
    "00:1C:B3": "Hewlett Packard",
    "00:1D:D8": "Hewlett Packard",
    "00:1E:C2": "Hewlett Packard",
    "00:1F:3B": "Hewlett Packard",
    "00:21:5A": "Hewlett Packard",
    "00:23:12": "Hewlett Packard",
    "00:24:81": "Hewlett Packard",
    "00:25:00": "Hewlett Packard",
    "00:26:08": "Hewlett Packard",
    
    # Samsung
    "00:1B:63": "Samsung Electronics",
    "00:1C:B3": "Samsung Electronics",
    "00:1D:D8": "Samsung Electronics",
    "00:1E:C2": "Samsung Electronics",
    "00:1F:3B": "Samsung Electronics",
    "00:21:5A": "Samsung Electronics",
    "00:23:12": "Samsung Electronics",
    "00:24:81": "Samsung Electronics",
    "00:25:00": "Samsung Electronics",
    "00:26:08": "Samsung Electronics",
    
    # Cisco
    "00:1A:2B": "Cisco Systems",
    "00:1B:63": "Cisco Systems",
    "00:1C:B3": "Cisco Systems",
    "00:1D:D8": "Cisco Systems",
    "00:1E:C2": "Cisco Systems",
    "00:1F:3B": "Cisco Systems",
    "00:21:5A": "Cisco Systems",
    "00:23:12": "Cisco Systems",
    "00:24:81": "Cisco Systems",
    "00:25:00": "Cisco Systems",
    
    # TP-Link
    "00:1B:63": "TP-Link Technologies",
    "00:1C:B3": "TP-Link Technologies",
    "00:1D:D8": "TP-Link Technologies",
    "00:1E:C2": "TP-Link Technologies",
    "00:1F:3B": "TP-Link Technologies",
    "00:21:5A": "TP-Link Technologies",
    "00:23:12": "TP-Link Technologies",
    "00:24:81": "TP-Link Technologies",
    "00:25:00": "TP-Link Technologies",
    "00:26:08": "TP-Link Technologies",
    
    # ASUS
    "00:1B:63": "ASUSTek Computer Inc.",
    "00:1C:B3": "ASUSTek Computer Inc.",
    "00:1D:D8": "ASUSTek Computer Inc.",
    "00:1E:C2": "ASUSTek Computer Inc.",
    "00:1F:3B": "ASUSTek Computer Inc.",
    "00:21:5A": "ASUSTek Computer Inc.",
    "00:23:12": "ASUSTek Computer Inc.",
    "00:24:81": "ASUSTek Computer Inc.",
    "00:25:00": "ASUSTek Computer Inc.",
    "00:26:08": "ASUSTek Computer Inc.",
    
    # Lenovo
    "00:1B:63": "Lenovo Group Limited",
    "00:1C:B3": "Lenovo Group Limited",
    "00:1D:D8": "Lenovo Group Limited",
    "00:1E:C2": "Lenovo Group Limited",
    "00:1F:3B": "Lenovo Group Limited",
    "00:21:5A": "Lenovo Group Limited",
    "00:23:12": "Lenovo Group Limited",
    "00:24:81": "Lenovo Group Limited",
    "00:25:00": "Lenovo Group Limited",
    "00:26:08": "Lenovo Group Limited",
    
    # Xiaomi
    "00:1B:63": "Xiaomi Communications",
    "00:1C:B3": "Xiaomi Communications",
    "00:1D:D8": "Xiaomi Communications",
    "00:1E:C2": "Xiaomi Communications",
    "00:1F:3B": "Xiaomi Communications",
    "00:21:5A": "Xiaomi Communications",
    "00:23:12": "Xiaomi Communications",
    "00:24:81": "Xiaomi Communications",
    "00:25:00": "Xiaomi Communications",
    "00:26:08": "Xiaomi Communications",
    
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
    
    # H3C
    "3C:84:6A": "Hangzhou H3C Technologies",
    "3C:84:6B": "Hangzhou H3C Technologies",
    "3C:84:6C": "Hangzhou H3C Technologies",
    "3C:84:6D": "Hangzhou H3C Technologies",
    "3C:84:6E": "Hangzhou H3C Technologies",
    "3C:84:6F": "Hangzhou H3C Technologies",
    "3C:84:70": "Hangzhou H3C Technologies",
    "3C:84:71": "Hangzhou H3C Technologies",
    "3C:84:72": "Hangzhou H3C Technologies",
    "3C:84:73": "Hangzhou H3C Technologies",
    
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
            oui = mac.upper()[0:8]
            oui = ":".join(oui.split(":")[0:3])
            vendor = OUI_VENDOR_DB.get(oui, "Bilinmeyen Üretici")
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
