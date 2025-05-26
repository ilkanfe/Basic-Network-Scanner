import sys
from PyQt5.QtWidgets import QApplication
from src.gui.main_window import MainWindow
from src.utils.logger import setup_logger

def main():
    """Ana uygulama fonksiyonu."""
    # Logger'ı başlat
    logger = setup_logger(__name__)
    
    try:
        # GUI uygulamasını başlat
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
        
    except Exception as e:
        logger.error(f"Uygulama başlatma hatası: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 