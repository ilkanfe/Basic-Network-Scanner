import unittest
import importlib

class TestImports(unittest.TestCase):
    def test_required_libraries(self):
        """Gerekli kütüphanelerin yüklü olup olmadığını kontrol eder."""
        required_libraries = [
            'scapy',
            'nmap',
            'plotly',
            'matplotlib'
        ]
        
        for lib in required_libraries:
            with self.subTest(library=lib):
                try:
                    importlib.import_module(lib)
                except ImportError:
                    self.fail(f"{lib} kütüphanesi yüklü değil!")

if __name__ == '__main__':
    unittest.main() 