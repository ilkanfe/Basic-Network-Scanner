def test_libraries():
    libraries = {
        'scapy': 'import scapy.all as scapy',
        'nmap': 'import nmap',
        'matplotlib': 'import matplotlib',
        'plotly': 'import plotly',
        'flask': 'import flask',
        'tkinter': 'import tkinter'
    }
    
    results = []
    for lib_name, import_statement in libraries.items():
        try:
            exec(import_statement)
            results.append(f"{lib_name}: ✓ Başarıyla yüklendi")
        except ImportError as e:
            results.append(f"{lib_name}: ✗ Yüklenemedi - Hata: {str(e)}")
    
    with open('library_test_results.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(results))

if __name__ == '__main__':
    test_libraries() 