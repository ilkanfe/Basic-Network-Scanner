import sys
from src.utils.network_utils import get_mac_and_vendor

def test_router():
    """Router'ı test et"""
    print("\nRouter Testi:")
    print("-" * 50)
    router_ip = "192.168.1.1"  # Varsayılan router IP'si
    print(f"Router IP: {router_ip}")
    mac, vendor = get_mac_and_vendor(router_ip)
    if mac:
        print(f"MAC: {mac}")
        print(f"Üretici: {vendor}")
    else:
        print("Router MAC adresi bulunamadı!")
    print("-" * 50)

def test_local_ip():
    """Kendi IP'mizi test et"""
    print("\nKendi IP Testi:")
    print("-" * 50)
    local_ip = "192.168.1.102"  # Kendi IP adresiniz
    print(f"Local IP: {local_ip}")
    mac, vendor = get_mac_and_vendor(local_ip)
    if mac:
        print(f"MAC: {mac}")
        print(f"Üretici: {vendor}")
    else:
        print("Local MAC adresi bulunamadı!")
    print("-" * 50)

if __name__ == "__main__":
    print("MAC Adresi ve Üretici Tespiti Testi")
    print("=" * 50)
    
    # Önce router'ı test et
    test_router()
    
    # Sonra kendi IP'mizi test et
    test_local_ip() 