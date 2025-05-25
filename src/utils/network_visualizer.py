import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List, Optional
import os
from src.utils.logger import setup_logger
from datetime import datetime

class NetworkVisualizer:
    def __init__(self, output_dir: str = "reports"):
        """
        Ağ görselleştirici sınıfı başlatıcısı.
        
        Args:
            output_dir (str): Görselleştirmelerin kaydedileceği dizin
        """
        self.logger = setup_logger(__name__)
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def create_network_map(self, scan_results: Dict, filename: Optional[str] = None) -> str:
        """
        Ağ haritası oluşturur.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            filename (Optional[str]): Dosya adı
            
        Returns:
            str: Kaydedilen dosyanın yolu
        """
        try:
            if filename is None:
                filename = os.path.join(self.output_dir, f"network_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
                
            # NetworkX grafiği oluştur
            G = nx.Graph()
            
            # Hostları ekle
            for host in scan_results.get('hosts', []):
                ip = host.get('ip', '')
                os_info = host.get('os_info', {})
                os_name = os_info.get('name', 'Unknown')
                
                # Host düğümünü ekle
                G.add_node(ip, 
                          os=os_name,
                          open_ports=len([p for p, info in host.get('ports', {}).items() 
                                        if info.get('state') == 'open']))
                
            # Ağ bağlantılarını ekle
            for i in range(len(scan_results.get('hosts', []))):
                for j in range(i + 1, len(scan_results.get('hosts', []))):
                    G.add_edge(scan_results['hosts'][i]['ip'], 
                             scan_results['hosts'][j]['ip'])
            
            # Görselleştirme
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G)
            
            # Düğümleri çiz
            nx.draw_networkx_nodes(G, pos,
                                 node_color='lightblue',
                                 node_size=1000,
                                 alpha=0.7)
            
            # Kenarları çiz
            nx.draw_networkx_edges(G, pos, alpha=0.5)
            
            # Etiketleri ekle
            labels = {node: f"{node}\n{G.nodes[node]['os']}\n{G.nodes[node]['open_ports']} açık port"
                     for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)
            
            plt.title("Ağ Haritası")
            plt.axis('off')
            
            # Görselleştirmeyi kaydet
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Ağ haritası kaydedildi: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Ağ haritası oluşturulamadı: {str(e)}")
            return "" 