import logging
import os

def setup_logger(name: str = None, log_file: str = 'logs/app.log', level: int = logging.INFO) -> logging.Logger:
    """
    Merkezi log ayarı. Hem konsola hem dosyaya log yazar.
    Args:
        name (str): Logger adı (modül adı genellikle)
        log_file (str): Log dosyasının yolu
        level (int): Log seviyesi
    Returns:
        logging.Logger: Ayarlanmış logger nesnesi
    """
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))

    logger = logging.getLogger(name)
    logger.setLevel(level)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')

    # Konsol handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Dosya handler
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Handler tekrarını önle
    logger.propagate = False

    return logger 