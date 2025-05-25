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
