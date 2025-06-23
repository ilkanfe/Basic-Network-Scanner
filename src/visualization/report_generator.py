import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from typing import Dict, List
import os
from datetime import datetime
from weasyprint import HTML

class ReportGenerator:
    def __init__(self):
        """Rapor oluşturucu sınıfı başlatıcısı."""
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def create_port_heatmap(self, scan_results: Dict) -> str:
        """
        Port tarama sonuçları için ısı haritası oluşturur.
        
        Args:
            scan_results (Dict): Tarama sonuçları
            
        Returns:
            str: Oluşturulan grafik dosyasının yolu
        """
        # TCP ve UDP portları için veri hazırla
        tcp_ports_data = scan_results.get('tcp_ports', {})
        udp_ports_data = scan_results.get('udp_ports', {})

        tcp_ports = list(tcp_ports_data.keys())
        udp_ports = list(udp_ports_data.keys())
        
        # Port durumlarını renk kodlarına dönüştür
        tcp_colors = ['green' if tcp_ports_data.get(p) == 'open' else 'red' for p in tcp_ports]
        udp_colors = ['green' if udp_ports_data.get(p) == 'open' else 'red' for p in udp_ports]
        
        # Plotly ile ısı haritası oluştur
        fig = make_subplots(rows=2, cols=1, subplot_titles=('TCP Ports', 'UDP Ports'))
        
        # TCP portları için ısı haritası
        fig.add_trace(
            go.Scatter(
                x=tcp_ports,
                y=['TCP'] * len(tcp_ports),
                mode='markers',
                marker=dict(
                    size=15,
                    color=tcp_colors,
                    symbol='square'
                ),
                name='TCP'
            ),
            row=1, col=1
        )
        
        # UDP portları için ısı haritası
        fig.add_trace(
            go.Scatter(
                x=udp_ports,
                y=['UDP'] * len(udp_ports),
                mode='markers',
                marker=dict(
                    size=15,
                    color=udp_colors,
                    symbol='square'
                ),
                name='UDP'
            ),
            row=2, col=1
        )
        
        # Grafik düzenini ayarla
        fig.update_layout(
            title='Port Scan Results',
            showlegend=False,
            height=400
        )
        
        # Grafiği kaydet
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'port_heatmap_{timestamp}.html'
        filepath = os.path.join(self.report_dir, filename)
        fig.write_html(filepath)
        
        return filepath
    
    def create_service_pie_chart(self, services: Dict) -> str:
        """
        Servis dağılımı için pasta grafik oluşturur.
        
        Args:
            services (Dict): Servis bilgileri
            
        Returns:
            str: Oluşturulan grafik dosyasının yolu
        """
        # Servis türlerini say
        service_counts = {}
        for port, info in services.items():
            service_name = info.get('name', 'unknown')
            service_counts[service_name] = service_counts.get(service_name, 0) + 1
        
        # Plotly ile pasta grafik oluştur
        fig = go.Figure(data=[go.Pie(
            labels=list(service_counts.keys()),
            values=list(service_counts.values()),
            hole=.3
        )])
        
        # Grafik düzenini ayarla
        fig.update_layout(
            title='Service Distribution',
            height=500
        )
        
        # Grafiği kaydet
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'service_pie_{timestamp}.html'
        filepath = os.path.join(self.report_dir, filename)
        fig.write_html(filepath)
        
        return filepath
    
    def create_os_detection_bar(self, os_results: Dict) -> str:
        """
        İşletim sistemi tespit sonuçları için çubuk grafik oluşturur.
        
        Args:
            os_results (Dict): İşletim sistemi tespit sonuçları
            
        Returns:
            str: Oluşturulan grafik dosyasının yolu
        """
        # Yöntemlere göre sonuçları hazırla
        methods = ['TTL Analysis', 'TCP Stack', 'Nmap']
        results = [
            os_results['ttl_analysis'].get('os', 'Unknown'),
            os_results['stack_analysis'].get('behavior', 'Unknown'),
            os_results['nmap_detection'].get('name', 'Unknown') if os_results.get('nmap_detection') else 'Unknown'
        ]
        
        # Plotly ile çubuk grafik oluştur
        fig = go.Figure(data=[
            go.Bar(
                x=methods,
                y=[1 if r else 0 for r in results],
                text=results,
                textposition='auto',
            )
        ])
        
        # Grafik düzenini ayarla
        fig.update_layout(
            title='Operating System Detection Results',
            yaxis_title='Successful Detection',
            height=400
        )
        
        # Grafiği kaydet
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'os_detection_{timestamp}.html'
        filepath = os.path.join(self.report_dir, filename)
        fig.write_html(filepath)
        
        return filepath
    
    def generate_report(self, scan_results: Dict, services: Dict, os_results: Dict) -> str:
        """
        Tüm tarama sonuçları için kapsamlı rapor oluşturur.
        
        Args:
            scan_results (Dict): Port tarama sonuçları
            services (Dict): Servis tespit sonuçları
            os_results (Dict): İşletim sistemi tespit sonuçları
            
        Returns:
            str: Oluşturulan rapor dosyasının yolu
        """
        port_heatmap = self.create_port_heatmap(scan_results)
        service_pie = self.create_service_pie_chart(services)
        os_bar = self.create_os_detection_bar(os_results)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Özet bölümü
        summary = f"""
        <div class="section">
            <h2>Summary</h2>
            <p>This report contains the scan results for {scan_results.get('target', 'Unknown')}.</p>
            <p>Total {len(scan_results.get('tcp_ports', {}))} TCP ports and {len(scan_results.get('udp_ports', {}))} UDP ports were scanned.</p>
            <p>Operating system detection: {os_results.get('name', 'Unknown')}</p>
        </div>
        """
        
        # Güvenlik önerileri
        security_recommendations = f"""
        <div class="section">
            <h2>Security Recommendations</h2>
            <ul>
        """
        
        for port, state in scan_results.get('tcp_ports', {}).items():
            if state == 'open':
                security_recommendations += f"<li>Port {port} is open.</li>"
        
        for port, state in scan_results.get('udp_ports', {}).items():
            if state == 'open':
                security_recommendations += f"<li>Port {port} is open.</li>"
        
        security_recommendations += """
            </ul>
        </div>
        """
        
        report = f"""
        <html>
        <head>
            <title>Network Scan Report - {timestamp}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin-bottom: 30px; }}
                h1, h2 {{ color: #333; }}
                iframe {{ border: none; width: 100%; height: 500px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-4">Network Scan Report</h1>
                <p>Generated At: {timestamp}</p>
                
                {summary}
                
                <div class="section">
                    <h2>Port Scan Results</h2>
                    <iframe src="{os.path.basename(port_heatmap)}"></iframe>
                </div>
                
                <div class="section">
                    <h2>Service Distribution</h2>
                    <iframe src="{os.path.basename(service_pie)}"></iframe>
                </div>
                
                <div class="section">
                    <h2>Operating System Detection</h2>
                    <iframe src="{os.path.basename(os_bar)}"></iframe>
                </div>
                
                {security_recommendations}
                
                <div class="section">
                    <h2>Detailed Results</h2>
                    <pre>{json.dumps(scan_results, indent=2)}</pre>
                    <pre>{json.dumps(services, indent=2)}</pre>
                    <pre>{json.dumps(os_results, indent=2)}</pre>
                </div>
            </div>
        </body>
        </html>
        """
        
        filename = f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        filepath = os.path.join(self.report_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # PDF rapor oluştur
        pdf_filename = f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        pdf_filepath = os.path.join(self.report_dir, pdf_filename)
        HTML(string=report).write_pdf(pdf_filepath)
        
        return filepath
