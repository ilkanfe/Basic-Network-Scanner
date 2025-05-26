from src.scanner.device_detector import DeviceDetector

def main():
    detector = DeviceDetector()
    devices = detector.get_all_devices_from_arp()
    if not devices:
        print("Ağda cihaz bulunamadı veya ARP tablosu boş.")
    else:
        print("Ağdaki cihazlar (IP ve MAC adresleri):")
        for d in devices:
            print(f"IP: {d['ip']}  MAC: {d['mac']}")

if __name__ == "__main__":
    main() 