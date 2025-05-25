import platform
import os

def is_windows() -> bool:
    """
    Windows işletim sisteminde çalışıp çalışmadığını kontrol eder.
    Returns:
        bool: Windows ise True, değilse False
    """
    return platform.system().lower() == 'windows'

def is_linux() -> bool:
    """
    Linux işletim sisteminde çalışıp çalışmadığını kontrol eder.
    Returns:
        bool: Linux ise True, değilse False
    """
    return platform.system().lower() == 'linux'

def get_platform_specific_command(command: str) -> str:
    """
    Platforma özel komut döndürür. Örneğin, Windows'ta 'ping' komutu farklı parametreler alabilir.
    Args:
        command (str): Temel komut
    Returns:
        str: Platforma özel komut
    """
    if is_windows():
        if command == 'ping':
            return 'ping -n 1'
        elif command == 'arp':
            return 'arp -a'
    return command 