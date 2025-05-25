import pytest
import os
import json
from src.utils.template_manager import TemplateManager

@pytest.fixture
def template_manager(tmp_path):
    """Test için şablon yöneticisi oluşturur."""
    return TemplateManager(template_dir=str(tmp_path))

def test_default_templates(template_manager):
    """Varsayılan şablonların yüklendiğini kontrol eder."""
    # PDF şablonu
    pdf_template = template_manager.load_template('pdf')
    assert pdf_template is not None
    assert 'title' in pdf_template
    assert 'sections' in pdf_template
    assert 'styles' in pdf_template
    
    # CSV şablonu
    csv_template = template_manager.load_template('csv')
    assert csv_template is not None
    assert 'headers' in csv_template
    assert 'delimiter' in csv_template
    assert 'encoding' in csv_template
    
    # JSON şablonu
    json_template = template_manager.load_template('json')
    assert json_template is not None
    assert 'indent' in json_template
    assert 'ensure_ascii' in json_template
    assert 'encoding' in json_template

def test_save_template(template_manager):
    """Yeni şablon kaydetme testi."""
    # Test şablonu
    test_template = {
        'title': 'Test Raporu',
        'sections': [
            {
                'name': 'Test Bölümü',
                'type': 'table',
                'columns': [
                    {'name': 'Test', 'width': '2*inch'}
                ]
            }
        ],
        'styles': {
            'title': {'fontSize': 20}
        }
    }
    
    # Şablonu kaydet
    assert template_manager.save_template('test', test_template)
    
    # Dosyanın oluşturulduğunu kontrol et
    filepath = os.path.join(template_manager.template_dir, 'test_template.json')
    assert os.path.exists(filepath)
    
    # İçeriği kontrol et
    with open(filepath, 'r', encoding='utf-8') as f:
        saved_template = json.load(f)
        assert saved_template['title'] == test_template['title']

def test_validate_template(template_manager):
    """Şablon doğrulama testi."""
    # Geçerli PDF şablonu
    valid_pdf = {
        'title': 'Test',
        'sections': [
            {
                'name': 'Test',
                'type': 'table',
                'columns': []
            }
        ],
        'styles': {}
    }
    assert template_manager.validate_template('pdf', valid_pdf)
    
    # Geçersiz PDF şablonu
    invalid_pdf = {
        'title': 'Test'
        # sections ve styles eksik
    }
    assert not template_manager.validate_template('pdf', invalid_pdf)
    
    # Geçerli CSV şablonu
    valid_csv = {
        'headers': ['Test'],
        'delimiter': ',',
        'encoding': 'utf-8'
    }
    assert template_manager.validate_template('csv', valid_csv)
    
    # Geçersiz CSV şablonu
    invalid_csv = {
        'headers': ['Test']
        # delimiter ve encoding eksik
    }
    assert not template_manager.validate_template('csv', invalid_csv)

def test_load_nonexistent_template(template_manager):
    """Var olmayan şablon yükleme testi."""
    assert template_manager.load_template('nonexistent') is None 