import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from typing import Dict, List, Optional
from src.utils.logger import setup_logger

class ScanVisualizer:
    def __init__(self):
        """Görselleştirme sınıfı başlatıcısı."""
        self.logger = setup_logger(__name__)
        
    def create_os_distribution_pie(self, os_results: List[Dict], output_path: Optional[str] = None) -> None:
        """
        İşletim sistemi dağılımını pasta grafiği olarak görselleştirir.
        
        Args:
            os_results (List[Dict]): OS tespit sonuçları
            output_path (Optional[str]): Çıktı dosyası yolu
        """
        try:
            # OS dağılımını hesapla
            os_counts = {}
            for result in os_results:
                os_name = result.get('name', 'Unknown')
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
                
            # Matplotlib ile pasta grafiği
            plt.figure(figsize=(10, 6))
            plt.pie(os_counts.values(), labels=os_counts.keys(), autopct='%1.1f%%')
            plt.title('İşletim Sistemi Dağılımı')
            
            if output_path:
                plt.savefig(output_path)
                plt.close()
            else:
                plt.show()
                
        except Exception as e:
            self.logger.error(f"OS dağılım grafiği oluşturma hatası: {str(e)}")
            
    def create_port_heatmap(self, scan_results: List[Dict], output_path: Optional[str] = None) -> None:
        """
        Port durumlarını ısı haritası olarak görselleştirir.
        
        Args:
            scan_results (List[Dict]): Tarama sonuçları
            output_path (Optional[str]): Çıktı dosyası yolu
        """
        try:
            # Veriyi hazırla
            data = []
            for result in scan_results:
                ip = result.get('ip', 'Unknown')
                for port, info in result.get('ports', {}).items():
                    data.append({
                        'IP': ip,
                        'Port': port,
                        'State': info.get('state', 'unknown')
                    })
                    
            df = pd.DataFrame(data)
            
            # Plotly ile ısı haritası
            fig = px.density_heatmap(
                df,
                x='Port',
                y='IP',
                z='State',
                title='Port Durumları Isı Haritası'
            )
            
            if output_path:
                fig.write_html(output_path)
            else:
                fig.show()
                
        except Exception as e:
            self.logger.error(f"Port ısı haritası oluşturma hatası: {str(e)}")
            
    def create_confidence_bar(self, os_results: List[Dict], output_path: Optional[str] = None) -> None:
        """
        OS tespit güven skorlarını çubuk grafik olarak görselleştirir.
        
        Args:
            os_results (List[Dict]): OS tespit sonuçları
            output_path (Optional[str]): Çıktı dosyası yolu
        """
        try:
            # Veriyi hazırla
            data = []
            for result in os_results:
                data.append({
                    'IP': result.get('ip', 'Unknown'),
                    'OS': result.get('name', 'Unknown'),
                    'Confidence': result.get('confidence', 0)
                })
                
            df = pd.DataFrame(data)
            
            # Plotly ile çubuk grafik
            fig = px.bar(
                df,
                x='IP',
                y='Confidence',
                color='OS',
                title='OS Tespit Güven Skorları',
                labels={'Confidence': 'Güven Skoru', 'IP': 'IP Adresi'}
            )
            
            if output_path:
                fig.write_html(output_path)
            else:
                fig.show()
                
        except Exception as e:
            self.logger.error(f"Güven skoru grafiği oluşturma hatası: {str(e)}")
            
    def create_interactive_dashboard(self, scan_results: List[Dict], output_path: str) -> None:
        """
        Tüm tarama sonuçlarını interaktif bir dashboard olarak görselleştirir.
        
        Args:
            scan_results (List[Dict]): Tarama sonuçları
            output_path (str): Çıktı dosyası yolu
        """
        try:
            import dash
            from dash import dcc, html
            from dash.dependencies import Input, Output
            
            app = dash.Dash(__name__)
            
            # Veriyi hazırla
            os_data = []
            port_data = []
            for result in scan_results:
                ip = result.get('ip', 'Unknown')
                
                # OS verisi
                os_data.append({
                    'IP': ip,
                    'OS': result.get('name', 'Unknown'),
                    'Confidence': result.get('confidence', 0)
                })
                
                # Port verisi
                for port, info in result.get('ports', {}).items():
                    port_data.append({
                        'IP': ip,
                        'Port': port,
                        'State': info.get('state', 'unknown'),
                        'Service': info.get('service', {}).get('name', 'unknown')
                    })
                    
            os_df = pd.DataFrame(os_data)
            port_df = pd.DataFrame(port_data)
            
            # Dashboard layout
            app.layout = html.Div([
                html.H1('Ağ Tarama Sonuçları Dashboard'),
                
                html.Div([
                    html.H2('İşletim Sistemi Dağılımı'),
                    dcc.Graph(
                        figure=px.pie(
                            os_df,
                            names='OS',
                            title='OS Dağılımı'
                        )
                    )
                ]),
                
                html.Div([
                    html.H2('Port Durumları'),
                    dcc.Graph(
                        figure=px.density_heatmap(
                            port_df,
                            x='Port',
                            y='IP',
                            z='State',
                            title='Port Durumları'
                        )
                    )
                ]),
                
                html.Div([
                    html.H2('OS Tespit Güven Skorları'),
                    dcc.Graph(
                        figure=px.bar(
                            os_df,
                            x='IP',
                            y='Confidence',
                            color='OS',
                            title='Güven Skorları'
                        )
                    )
                ])
            ])
            
            # Dashboard'ı HTML olarak kaydet
            app.run_server(debug=False)
            app.layout.to_html(output_path)
            
        except Exception as e:
            self.logger.error(f"Dashboard oluşturma hatası: {str(e)}") 