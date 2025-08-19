import ping3
import socket
import plotly.graph_objects as go
from datetime import datetime
from typing import List, Dict
import subprocess
from flask import Flask, render_template, request, jsonify, Response
import threading
import queue
import os
import csv
from io import StringIO
import shutil
import time

app = Flask(__name__)

class IPMonitor:
	def __init__(self):
		self.monitored_ips: Dict[str, Dict] = {}
		self.monitored_ports: Dict[str, List[int]] = {}
		self.data_queue = queue.Queue()
		self.is_running = False
		self.data_history: Dict[str, List[Dict]] = {}
		self.alerts: Dict[str, List[Dict]] = {}
		# 可配置阈值
		self.alert_thresholds = {
			'latency': 100,  # 延迟阈值（毫秒）
			'packet_loss': 5,  # 丢包率阈值（百分比）
			'port_status': True  # 端口状态变化告警
		}
		# 监控检查间隔（秒）
		self.check_interval = 1
		# 计算丢包率的滑动窗口大小（条）
		self.packet_loss_window_size = 20

	def add_ip(self, ip: str, ports: List[int] = None):
		"""添加要监控的IP地址"""
		if ip not in self.monitored_ips:
			self.monitored_ips[ip] = {
				'latency': None,
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
		if ip in self.alerts:
			del self.alerts[ip]

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
		except Exception:
			return False

	def run_mtr(self, ip: str) -> Dict:
		"""运行MTR命令"""
		try:
			# 检查系统是否存在 mtr 命令
			if not shutil.which('mtr'):
				return {
					'status': 'error',
					'error': '系统未安装 mtr 命令'
				}

			cmd = ['mtr', '-n', '-r', '-c', '1', ip]

			try:
				result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
				return {
					'status': 'success',
					'output': result.stdout,
					'error': result.stderr
				}
			except subprocess.TimeoutExpired:
				return {
					'status': 'error',
					'error': 'mtr 超时'
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

		# 检查丢包率告警（基于历史数据计算）
		if data.get('packet_loss') is not None and \
		   data['packet_loss'] > self.alert_thresholds['packet_loss']:
			alerts.append({
				'type': 'packet_loss',
				'message': f'丢包率过高: {data["packet_loss"]:.2f}%',
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
		writer.writerow(['时间', '延迟(ms)', '丢包率(%)', '状态', '端口状态', '告警'])

		# 写入数据
		for record in self.data_history[ip]:
			port_status = ','.join([f'{port}:{"开放" if status else "关闭"}'
								  for port, status in record.get('port_status', {}).items()])
			alerts = ','.join([alert['message'] for alert in record.get('alerts', [])])

			writer.writerow([
				record.get('timestamp'),
				record.get('latency'),
				record.get('packet_loss'),
				record.get('status'),
				port_status,
				alerts
			])

		return output.getvalue()

	def get_latency_graph(self, ip: str) -> str:
		"""生成延迟图表"""
		if ip not in self.data_history:
			return None

		records = self.data_history[ip]
		x_values = [record['timestamp'] for record in records]
		y_values = [record.get('latency') for record in records]

		# 创建多图表布局
		fig = go.Figure()

		# 延迟趋势图
		fig.add_trace(go.Scatter(
			x=x_values,
			y=y_values,
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

		records = self.data_history[ip]

		# 统一端口集合
		all_ports = set()
		for record in records:
			all_ports.update(record.get('port_status', {}).keys())
		ports = sorted(list(all_ports))

		# 时间戳
		timestamps = [record['timestamp'] for record in records]

		# 构建矩阵 [时间, 端口] -> 开放(1)/关闭(0)
		port_matrix = []
		for record in records:
			port_status = record.get('port_status', {})
			row = [1 if port_status.get(port) else 0 for port in ports]
			port_matrix.append(row)

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

		fig = go.Figure()

		# 按告警类型分组显示
		type_to_points: Dict[str, Dict[str, List]] = {}
		for alert in alerts:
			t = alert.get('type', 'unknown')
			if t not in type_to_points:
				type_to_points[t] = {'x': [], 'y': [], 'text': []}
			type_to_points[t]['x'].append(alert.get('timestamp'))
			type_to_points[t]['y'].append(1)
			type_to_points[t]['text'].append(alert.get('message'))

		for alert_type, series in type_to_points.items():
			fig.add_trace(go.Scatter(
				x=series['x'],
				y=series['y'],
				mode='markers',
				name=alert_type,
				text=series['text'],
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

	def _ping_via_system(self, ip: str) -> float:
		"""使用系统 ping 命令测量延迟，返回毫秒。失败返回 None。"""
		if not shutil.which('ping'):
			return None
		try:
			# -c 1 发送1个包，-w 1 总超时1秒
			result = subprocess.run(['ping', '-c', '1', '-w', '1', ip], capture_output=True, text=True)
			output = result.stdout
			# 优先解析 time=xx ms
			for line in output.splitlines():
				if 'time=' in line:
					try:
						# e.g., time=8.23 ms
						part = line.split('time=')[1]
						value = part.split()[0]
						return float(value)
					except Exception:
						continue
			# 其次解析 rtt 行 avg 值
			for line in output.splitlines():
				if 'rtt' in line or 'round-trip' in line:
					stats = line.split('=')[1].split('/')[1].strip()
					return float(stats)
		except Exception:
			return None
		return None

	def _tcp_latency_ms(self, ip: str, port: int, timeout_sec: float = 1.0) -> float:
		"""通过 TCP connect 握手测量近似延迟，返回毫秒，失败返回 None。"""
		try:
			start = time.monotonic()
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(timeout_sec)
			result = sock.connect_ex((ip, port))
			sock.close()
			if result == 0:
				end = time.monotonic()
				return (end - start) * 1000.0
		except Exception:
			return None
		return None

	def measure_latency_ms(self, ip: str) -> float:
		"""测量延迟（毫秒）。优先使用 ping3，失败则使用系统 ping，然后 TCP 握手作为兜底。"""
		# 尝试 ping3（无特权参数）
		try:
			latency_ms = ping3.ping(ip, timeout=1, unit='ms')
			if latency_ms is not None:
				return float(latency_ms)
		except TypeError:
			# 旧版本不支持某些参数时忽略
			try:
				latency = ping3.ping(ip, timeout=1)
				if latency is not None:
					return float(latency) * 1000.0
			except Exception:
				pass
		except Exception:
			pass

		# 回退到系统 ping
		sys_ping_ms = self._ping_via_system(ip)
		if sys_ping_ms is not None:
			return sys_ping_ms

		# 最后回退：TCP 握手延迟
		candidate_ports: List[int] = []
		if ip in self.monitored_ports and self.monitored_ports[ip]:
			candidate_ports = list(self.monitored_ports[ip])
		else:
			candidate_ports = [80, 443, 53]

		for port in candidate_ports:
			tcp_ms = self._tcp_latency_ms(ip, port, timeout_sec=1)
			if tcp_ms is not None:
				return tcp_ms

		return None

	def monitor_loop(self):
		"""监控循环（线程）"""
		while self.is_running:
			for ip in list(self.monitored_ips.keys()):
				try:
					# 检查延迟
					latency_ms = self.measure_latency_ms(ip)
					status = 'up' if latency_ms is not None else 'down'

					# 检查端口
					port_status = {}
					if ip in self.monitored_ports:
						for port in self.monitored_ports[ip]:
							port_status[port] = self.check_port(ip, port)

					# 运行MTR
					mtr_result = self.run_mtr(ip)

					# 更新数据
					current_data = {
						'latency': latency_ms if latency_ms is not None else None,
						'status': status,
						'last_check': datetime.now().isoformat(),
						'port_status': port_status,
						'mtr_result': mtr_result
					}

					self.monitored_ips[ip].update(current_data)

					# 计算基于滑动窗口的丢包率
					recent_records = self.data_history.get(ip, [])[- (self.packet_loss_window_size - 1):]
					latencies = [r.get('latency') for r in recent_records] + [current_data['latency']]
					total_count = len(latencies)
					lost_count = sum(1 for l in latencies if l is None)
					packet_loss = (lost_count / total_count * 100.0) if total_count > 0 else 0.0
					current_data['packet_loss'] = round(packet_loss, 2)

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

			time.sleep(self.check_interval)  # 间隔检查

	def start_monitoring(self):
		"""启动监控"""
		if not self.is_running:
			self.is_running = True
			threading.Thread(target=self.monitor_loop, daemon=True).start()

	def stop_monitoring(self):
		"""停止监控"""
		self.is_running = False

# 创建全局监控器实例
monitor = IPMonitor()

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/api/add_ip', methods=['POST'])
def api_add_ip():
	data = request.json or {}
	ip = data.get('ip')
	ports = data.get('ports', [])

	if not ip:
		return jsonify({'error': 'IP地址不能为空'}), 400

	monitor.add_ip(ip, ports)
	return jsonify({'message': f'已添加IP: {ip}'})

@app.route('/api/remove_ip', methods=['POST'])
def api_remove_ip():
	data = request.json or {}
	ip = data.get('ip')

	if not ip:
		return jsonify({'error': 'IP地址不能为空'}), 400

	monitor.remove_ip(ip)
	return jsonify({'message': f'已移除IP: {ip}'})

@app.route('/api/add_ports', methods=['POST'])
def api_add_ports():
	data = request.json or {}
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
		return Response(
			csv_data,
			mimetype='text/csv',
			headers={
				'Content-Disposition': f'attachment; filename="{ip}_monitoring_data.csv"'
			}
		)
	return jsonify({'error': '没有找到该IP的数据'}), 404

@app.route('/api/alerts/<ip>')
def get_alerts(ip):
	if ip in monitor.alerts:
		return jsonify({'alerts': monitor.alerts[ip]})
	return jsonify({'error': '没有找到该IP的告警数据'}), 404

if __name__ == '__main__':
	# 启动监控
	monitor.start_monitoring()

	# 启动Flask应用
	app.run(debug=False, use_reloader=False)