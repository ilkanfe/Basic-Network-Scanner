import logging
from typing import Optional

def handle_error(logger: logging.Logger, error_msg: str, raise_error: bool = True) -> Optional[ValueError]:
    """
    Hata mesajını loglar ve isteğe bağlı olarak ValueError fırlatır.
    Args:
        logger (logging.Logger): Logger nesnesi
        error_msg (str): Hata mesajı
        raise_error (bool): Hata fırlatılsın mı?
    Returns:
        Optional[ValueError]: Fırlatılan hata (raise_error=True ise)
    """
    logger.error(error_msg)
    if raise_error:
        raise ValueError(error_msg)
    return None 