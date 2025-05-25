import json
import os
from typing import Dict, Optional
from src.utils.logger import setup_logger

class TemplateManager:
    def __init__(self, template_dir: str = "templates"):
        """
        Şablon yöneticisi sınıfı başlatıcısı.
        
        Args:
            template_dir (str): Şablon dosyalarının bulunduğu dizin
        """
        self.logger = setup_logger(__name__)
        self.template_dir = template_dir
        self.templates = {}
        
        # Şablon dizinini oluştur
        os.makedirs(template_dir, exist_ok=True)
        
        # Varsayılan şablonları yükle
        self._load_default_templates()
        
    def _load_default_templates(self):
        """Varsayılan şablonları yükler."""
        default_templates = {
            'pdf': {
                'title': 'Ağ Tarama Raporu',
                'sections': [
                    {
                        'name': 'Tarama Bilgileri',
                        'type': 'table',
                        'columns': [
                            {'name': 'Tarama Hedefi', 'width': '2*inch'},
                            {'name': 'Değer', 'width': '4*inch'}
                        ]
                    },
                    {
                        'name': 'İşletim Sistemi Dağılımı',
                        'type': 'table',
                        'columns': [
                            {'name': 'İşletim Sistemi', 'width': '4*inch'},
                            {'name': 'Host Sayısı', 'width': '2*inch'}
                        ]
                    },
                    {
                        'name': 'Port İstatistikleri',
                        'type': 'table',
                        'columns': [
                            {'name': 'Port', 'width': '2*inch'},
                            {'name': 'Durum', 'width': '2*inch'},
                            {'name': 'Host Sayısı', 'width': '2*inch'}
                        ]
                    }
                ],
                'styles': {
                    'title': {
                        'fontSize': 24,
                        'spaceAfter': 30
                    },
                    'heading': {
                        'fontSize': 16,
                        'spaceAfter': 12
                    },
                    'table': {
                        'headerBackground': 'grey',
                        'headerTextColor': 'whitesmoke',
                        'fontSize': 12,
                        'padding': 12
                    }
                }
            },
            'csv': {
                'headers': [
                    'IP',
                    'OS',
                    'OS Confidence',
                    'Port',
                    'State',
                    'Service',
                    'Version'
                ],
                'delimiter': ',',
                'encoding': 'utf-8'
            },
            'json': {
                'indent': 4,
                'ensure_ascii': False,
                'encoding': 'utf-8'
            }
        }
        
        # Varsayılan şablonları kaydet
        for template_type, template in default_templates.items():
            self.save_template(template_type, template)
            
    def save_template(self, template_type: str, template: Dict) -> bool:
        """
        Yeni şablon kaydeder.
        
        Args:
            template_type (str): Şablon türü ('pdf', 'csv', 'json')
            template (Dict): Şablon içeriği
            
        Returns:
            bool: Başarılı ise True
        """
        try:
            filepath = os.path.join(self.template_dir, f"{template_type}_template.json")
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=4, ensure_ascii=False)
                
            self.templates[template_type] = template
            self.logger.info(f"Şablon kaydedildi: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Şablon kaydetme hatası: {str(e)}")
            return False
            
    def load_template(self, template_type: str) -> Optional[Dict]:
        """
        Şablon yükler.
        
        Args:
            template_type (str): Şablon türü ('pdf', 'csv', 'json')
            
        Returns:
            Optional[Dict]: Şablon içeriği veya None
        """
        try:
            # Önce önbellekten kontrol et
            if template_type in self.templates:
                return self.templates[template_type]
                
            # Dosyadan yükle
            filepath = os.path.join(self.template_dir, f"{template_type}_template.json")
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    template = json.load(f)
                self.templates[template_type] = template
                return template
                
            self.logger.warning(f"Şablon bulunamadı: {template_type}")
            return None
            
        except Exception as e:
            self.logger.error(f"Şablon yükleme hatası: {str(e)}")
            return None
            
    def validate_template(self, template_type: str, template: Dict) -> bool:
        """
        Şablon doğrular.
        
        Args:
            template_type (str): Şablon türü ('pdf', 'csv', 'json')
            template (Dict): Şablon içeriği
            
        Returns:
            bool: Geçerli ise True
        """
        try:
            if template_type == 'pdf':
                required_fields = ['title', 'sections', 'styles']
                if not all(field in template for field in required_fields):
                    return False
                    
                for section in template['sections']:
                    if not all(field in section for field in ['name', 'type', 'columns']):
                        return False
                        
            elif template_type == 'csv':
                required_fields = ['headers', 'delimiter', 'encoding']
                if not all(field in template for field in required_fields):
                    return False
                    
            elif template_type == 'json':
                required_fields = ['indent', 'ensure_ascii', 'encoding']
                if not all(field in template for field in required_fields):
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Şablon doğrulama hatası: {str(e)}")
            return False 