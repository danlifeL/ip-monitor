import asyncio
import ping3
import socket
import time
import json
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from typing import List, Dict, Optional
import subprocess
from flask import Flask, render_template, request, jsonify, send_file
import threading
import queue
import os
import csv
from io import StringIO
import numpy as np

app = Flask(__name__)

class IPMonitor:
    def __init__(self):
        self.monitored_ips = {}
        self.monitored_ports = {}
        self.data_queue = queue.Queue()
        self.is_running = False
        self.data_history = {}
        self.alerts = {}
        self.alert_thresholds = {
            'latency': 100,  # 延迟阈值（毫秒）
            'packet_loss': 5,  # 丢包率阈值（百分比）
            'port_status': True  # 端口状态变化告警
        }

    def add_ip(self, ip: str, ports: List[int] = None):
        """添加要监控的IP地址"""
        if ip not in self.monitored_ips:
            self.monitored_ips[ip] = {
                'latency': [],
                'status': 'unknown',
                'last_check': None,
                'alerts': []
            }
            if ports:
                self.monitored_ports[ip] = ports
            self.data_history[ip] = []
            self.alerts[ip] = []

    def remove_ip(self, ip: str):
        """移除监控的IP地址"""
        if ip in self.monitored_ips:
            del self.monitored_ips[ip]
        if ip in self.monitored_ports:
            del self.monitored_ports[ip]
        if ip in self.data_history:
            del self.data_history[ip]

    def add_ports(self, ip: str, ports: List[int]):
        """为指定IP添加端口监控"""
        if ip in self.monitored_ips:
            if ip not in self.monitored_ports:
                self.monitored_ports[ip] = []
            self.monitored_ports[ip].extend(ports)

    def check_port(self, ip: str, port: int) -> bool:
        """检查端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def run_mtr(self, ip: str) -> Dict:
        """运行MTR命令"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['mtr', '-n', '-r', '-c', '1', ip]
            else:  # Linux/Unix
                cmd = ['mtr', '-n', '-r', '-c', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return {
                'status': 'success',
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def check_alerts(self, ip: str, data: Dict):
        """检查是否需要发送告警"""
        alerts = []
        
        # 检查延迟告警
        if data.get('latency') and data['latency'] > self.alert_thresholds['latency']:
            alerts.append({
                'type': 'latency',
                'message': f'延迟过高: {data["latency"]:.2f}ms',
                'timestamp': datetime.now().isoformat()
            })

        # 检查端口状态告警
        if data.get('port_status'):
            for port, is_open in data['port_status'].items():
                if not is_open:
                    alerts.append({
                        'type': 'port',
                        'message': f'端口 {port} 关闭',
                        'timestamp': datetime.now().isoformat()
                    })

        # 检查MTR告警
        if data.get('mtr_result') and data['mtr_result'].get('status') == 'success':
            mtr_output = data['mtr_result']['output']
            if 'Loss%' in mtr_output:
                loss_percentage = float(mtr_output.split('Loss%')[1].split()[0])
                if loss_percentage > self.alert_thresholds['packet_loss']:
                    alerts.append({
                        'type': 'packet_loss',
                        'message': f'丢包率过高: {loss_percentage}%',
                        'timestamp': datetime.now().isoformat()
                    })

        # 更新告警状态
        if alerts:
            self.alerts[ip].extend(alerts)
            self.monitored_ips[ip]['alerts'] = alerts

    def export_data(self, ip: str) -> str:
        """导出监控数据为CSV格式"""
        if ip not in self.data_history:
            return None

        output = StringIO()
        writer = csv.writer(output)
        
        # 写入表头
        writer.writerow(['时间', '延迟(ms)', '状态', '端口状态', '告警'])
        
        # 写入数据
        for record in self.data_history[ip]:
            port_status = ','.join([f'{port}:{"开放" if status else "关闭"}' 
                                  for port, status in record.get('port_status', {}).items()])
            alerts = ','.join([alert['message'] for alert in record.get('alerts', [])])
            
            writer.writerow([
                record['timestamp'],
                record['latency'],
                record['status'],
                port_status,
                alerts
            ])

        return output.getvalue()

    def get_latency_graph(self, ip: str) -> str:
        """生成延迟图表"""
        if ip not in self.data_history:
            return None

        df = pd.DataFrame(self.data_history[ip])
        
        # 创建多图表布局
        fig = go.Figure()
        
        # 延迟趋势图
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['latency'],
            mode='lines+markers',
            name='延迟',
            line=dict(color='#17BECF')
        ))

        # 添加告警阈值线
        fig.add_hline(y=self.alert_thresholds['latency'], 
                     line_dash="dash", 
                     line_color="red",
                     annotation_text="告警阈值",
                     annotation_position="right")

        # 更新布局
        fig.update_layout(
            title=f'{ip} 延迟监测',
            xaxis_title='时间',
            yaxis_title='延迟 (ms)',
            template='plotly_dark',
            showlegend=True,
            height=400
        )

        return fig.to_html(full_html=False)

    def get_port_status_graph(self, ip: str) -> str:
        """生成端口状态图表"""
        if ip not in self.data_history:
            return None

        df = pd.DataFrame(self.data_history[ip])
        
        # 创建端口状态热力图
        port_data = []
        timestamps = []
        ports = set()
        
        for record in df['port_status']:
            timestamps.append(record['timestamp'])
            for port, status in record.items():
                ports.add(port)
                port_data.append(1 if status else 0)

        ports = sorted(list(ports))
        port_matrix = np.array(port_data).reshape(len(timestamps), len(ports))

        fig = go.Figure(data=go.Heatmap(
            z=port_matrix,
            x=ports,
            y=timestamps,
            colorscale='RdYlGn',
            showscale=True,
            text=[[f"{'开放' if val else '关闭'}" for val in row] for row in port_matrix],
            texttemplate='%{text}',
            textfont={"size": 10}
        ))

        fig.update_layout(
            title=f'{ip} 端口状态历史',
            xaxis_title='端口',
            yaxis_title='时间',
            template='plotly_dark',
            height=400
        )

        return fig.to_html(full_html=False)

    def get_alert_history_graph(self, ip: str) -> str:
        """生成告警历史图表"""
        if ip not in self.alerts:
            return None

        alerts = self.alerts[ip]
        if not alerts:
            return None

        df = pd.DataFrame(alerts)
        
        fig = go.Figure()
        
        # 按告警类型分组显示
        for alert_type in df['type'].unique():
            type_data = df[df['type'] == alert_type]
            fig.add_trace(go.Scatter(
                x=type_data['timestamp'],
                y=[1] * len(type_data),
                mode='markers',
                name=alert_type,
                text=type_data['message'],
                hoverinfo='text'
            ))

        fig.update_layout(
            title=f'{ip} 告警历史',
            xaxis_title='时间',
            yaxis_title='告警类型',
            template='plotly_dark',
            showlegend=True,
            height=200
        )

        return fig.to_html(full_html=False)

    async def monitor_loop(self):
        """监控循环"""
        while self.is_running:
            for ip in list(self.monitored_ips.keys()):
                try:
                    # 检查延迟
                    latency = ping3.ping(ip)
                    status = 'up' if latency is not None else 'down'
                    
                    # 检查端口
                    port_status = {}
                    if ip in self.monitored_ports:
                        for port in self.monitored_ports[ip]:
                            port_status[port] = self.check_port(ip, port)

                    # 运行MTR
                    mtr_result = self.run_mtr(ip)

                    # 更新数据
                    current_data = {
                        'latency': latency * 1000 if latency else None,
                        'status': status,
                        'last_check': datetime.now().isoformat(),
                        'port_status': port_status,
                        'mtr_result': mtr_result
                    }
                    
                    self.monitored_ips[ip].update(current_data)

                    # 检查告警
                    self.check_alerts(ip, current_data)

                    # 保存历史数据
                    self.data_history[ip].append({
                        'timestamp': datetime.now().isoformat(),
                        **current_data,
                        'alerts': self.alerts[ip][-5:]  # 只保存最近5条告警
                    })

                    # 限制历史数据长度
                    if len(self.data_history[ip]) > 100:
                        self.data_history[ip] = self.data_history[ip][-100:]

                except Exception as e:
                    self.monitored_ips[ip]['status'] = 'error'
                    self.monitored_ips[ip]['error'] = str(e)

            await asyncio.sleep(1)  # 每秒检查一次

    def start_monitoring(self):
        """启动监控"""
        if not self.is_running:
            self.is_running = True
            asyncio.run(self.monitor_loop())

    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False

# 创建全局监控器实例
monitor = IPMonitor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/add_ip', methods=['POST'])
def add_ip():
    data = request.json
    ip = data.get('ip')
    ports = data.get('ports', [])
    
    if not ip:
        return jsonify({'error': 'IP地址不能为空'}), 400
    
    monitor.add_ip(ip, ports)
    return jsonify({'message': f'已添加IP: {ip}'})

@app.route('/api/remove_ip', methods=['POST'])
def remove_ip():
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP地址不能为空'}), 400
    
    monitor.remove_ip(ip)
    return jsonify({'message': f'已移除IP: {ip}'})

@app.route('/api/add_ports', methods=['POST'])
def add_ports():
    data = request.json
    ip = data.get('ip')
    ports = data.get('ports', [])
    
    if not ip or not ports:
        return jsonify({'error': 'IP地址和端口不能为空'}), 400
    
    monitor.add_ports(ip, ports)
    return jsonify({'message': f'已为 {ip} 添加端口监控'})

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'monitored_ips': monitor.monitored_ips,
        'data_history': monitor.data_history
    })

@app.route('/api/graph/<ip>/<graph_type>')
def get_graph(ip, graph_type):
    if graph_type == 'latency':
        graph_html = monitor.get_latency_graph(ip)
    elif graph_type == 'ports':
        graph_html = monitor.get_port_status_graph(ip)
    elif graph_type == 'alerts':
        graph_html = monitor.get_alert_history_graph(ip)
    else:
        return jsonify({'error': '不支持的图表类型'}), 400

    if graph_html:
        return jsonify({'graph': graph_html})
    return jsonify({'error': '没有找到该IP的数据'}), 404

@app.route('/api/export/<ip>')
def export_data(ip):
    csv_data = monitor.export_data(ip)
    if csv_data:
        return send_file(
            StringIO(csv_data),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'{ip}_monitoring_data.csv'
        )
    return jsonify({'error': '没有找到该IP的数据'}), 404

@app.route('/api/alerts/<ip>')
def get_alerts(ip):
    if ip in monitor.alerts:
        return jsonify({'alerts': monitor.alerts[ip]})
    return jsonify({'error': '没有找到该IP的告警数据'}), 404

def start_monitor_thread():
    monitor.start_monitoring()

if __name__ == '__main__':
    # 启动监控线程
    monitor_thread = threading.Thread(target=start_monitor_thread)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # 启动Flask应用
    app.run(debug=True) 