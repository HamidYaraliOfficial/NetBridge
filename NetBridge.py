import sys
import json
import sqlite3
import platform
import psutil
import scapy.all as scapy
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QTextEdit, QComboBox, QLabel,
    QTableWidget, QTableWidgetItem, QLineEdit, QFileDialog,
    QCheckBox, QSpinBox, QGroupBox, QFormLayout, QMessageBox,
    QProgressBar, QMenuBar, QMenu, QDialog, QInputDialog,
    QStatusBar, QToolBar, QTreeWidget, QTreeWidgetItem, QSplitter,
    QDockWidget, QSlider, QDateTimeEdit, QCalendarWidget
)
from PyQt6.QtGui import QAction, QIcon, QColor, QPalette, QFont, QPixmap
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSettings, QSize, QDateTime
import os
import datetime
import logging
import threading
import queue
import socket
import netaddr
import re
from typing import Dict, List, Optional, Tuple
import qdarkstyle
import qstylizer.style
import subprocess
import time
import hashlib
import base64
import ipaddress
import uuid
import xml.etree.ElementTree as ET
import yaml
import csv
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import dns.resolver
import requests
import paramiko
import wakeonlan
import snmp
import schedule
import ping3
import portalocker

# Setup logging
logging.basicConfig(filename='netbridge.log', level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

class ThemeManager:
    @staticmethod
    def apply_windows11_theme(app):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
        palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
        palette.setColor(QPalette.ColorRole.Button, QColor(230, 230, 230))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
        palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
        app.setPalette(palette)
    
    @staticmethod
    def apply_dark_theme(app):
        app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt6'))
    
    @staticmethod
    def apply_red_blue_theme(app):
        style = qstylizer.style.StyleSheet()
        style.QWidget.background_color = '#1E3A8A'
        style.QWidget.color = '#F9FAFB'
        style.QPushButton.background_color = '#DC2626'
        style.QPushButton.color = '#FFFFFF'
        style.QPushButton.border_radius = '4px'
        style.QPushButton.padding = '6px'
        style.QTextEdit.background_color = '#2B4C8B'
        style.QTextEdit.color = '#FFFFFF'
        style.QTextEdit.border = '1px solid #4B6CB7'
        style.QTableWidget.background_color = '#2B4C8B'
        style.QTableWidget.color = '#FFFFFF'
        style.QTableWidget.gridline_color = '#4B6CB7'
        style.QComboBox.background_color = '#2B4C8B'
        style.QComboBox.color = '#FFFFFF'
        style.QComboBox.border = '1px solid #4B6CB7'
        app.setStyleSheet(style.toString())
        
    @staticmethod
    def apply_default_theme(app):
        app.setStyleSheet('')
        app.setStyle('Fusion')

class LanguageManager:
    translations = {
        'en': {
            'title': 'NetBridge - Network Management Suite',
            'diagnostics': 'Network Diagnostics',
            'optimizer': 'Network Optimizer',
            'simulator': 'Network Simulator',
            'knowledge': 'Knowledge Base',
            'config': 'Configuration Manager',
            'security': 'Security Analyzer',
            'logs': 'Log Analyzer',
            'scan': 'Scan Network',
            'optimize': 'Optimize Settings',
            'simulate': 'Start Simulation',
            'save_config': 'Save Configuration',
            'load_config': 'Load Configuration',
            'language': 'Language',
            'theme': 'Theme',
            'status': 'Status: Ready',
            'start': 'Start',
            'stop': 'Stop',
            'settings': 'Settings',
            'export': 'Export Data',
            'import': 'Import Data',
            'advanced': 'Advanced Options',
            'reports': 'Generate Reports',
            'network_map': 'Network Map',
            'performance': 'Performance Monitor',
            'help': 'Help',
            'backup': 'Backup Data',
            'restore': 'Restore Data',
            'clear_logs': 'Clear Logs',
            'advanced_settings': 'Advanced Settings',
            'network_stats': 'Network Statistics',
            'traffic_analysis': 'Traffic Analysis',
            'schedule_scan': 'Schedule Scan',
            'wake_on_lan': 'Wake on LAN',
            'port_scan': 'Port Scan',
            'vulnerability_scan': 'Vulnerability Scan',
            'firewall_rules': 'Firewall Rules',
            'snmp_monitor': 'SNMP Monitor',
            'dns_check': 'DNS Check',
            'export_pcap': 'Export PCAP',
            'import_pcap': 'Import PCAP'
        },
        'fa': {
            'title': 'نت‌بریج - مجموعه مدیریت شبکه',
            'diagnostics': 'عیب‌یابی شبکه',
            'optimizer': 'بهینه‌ساز شبکه',
            'simulator': 'شبیه‌ساز شبکه',
            'knowledge': 'پایگاه دانش',
            'config': 'مدیریت تنظیمات',
            'security': 'تحلیل‌گر امنیتی',
            'logs': 'تحلیل‌گر لاگ‌ها',
            'scan': 'اسکن شبکه',
            'optimize': 'بهینه‌سازی تنظیمات',
            'simulate': 'شروع شبیه‌سازی',
            'save_config': 'ذخیره تنظیمات',
            'load_config': 'بارگذاری تنظیمات',
            'language': 'زبان',
            'theme': 'تم',
            'status': 'وضعیت: آماده',
            'start': 'شروع',
            'stop': 'توقف',
            'settings': 'تنظیمات',
            'export': 'صادرات داده‌ها',
            'import': 'واردات داده‌ها',
            'advanced': 'گزینه‌های پیشرفته',
            'reports': 'تولید گزارش‌ها',
            'network_map': 'نقشه شبکه',
            'performance': 'نظارت بر عملکرد',
            'help': 'راهنما',
            'backup': 'پشتیبان‌گیری داده‌ها',
            'restore': 'بازیابی داده‌ها',
            'clear_logs': 'پاک کردن لاگ‌ها',
            'advanced_settings': 'تنظیمات پیشرفته',
            'network_stats': 'آمار شبکه',
            'traffic_analysis': 'تحلیل ترافیک',
            'schedule_scan': 'زمان‌بندی اسکن',
            'wake_on_lan': 'بیدار کردن از طریق شبکه',
            'port_scan': 'اسکن پورت',
            'vulnerability_scan': 'اسکن آسیب‌پذیری',
            'firewall_rules': 'قوانین فایروال',
            'snmp_monitor': 'نظارت SNMP',
            'dns_check': 'بررسی DNS',
            'export_pcap': 'صادرات PCAP',
            'import_pcap': 'واردات PCAP'
        },
        'zh': {
            'title': 'NetBridge - 网络管理套件',
            'diagnostics': '网络诊断',
            'optimizer': '网络优化器',
            'simulator': '网络模拟器',
            'knowledge': '知识库',
            'config': '配置管理器',
            'security': '安全分析器',
            'logs': '日志分析器',
            'scan': '扫描网络',
            'optimize': '优化设置',
            'simulate': '开始模拟',
            'save_config': '保存配置',
            'load_config': '加载配置',
            'language': '语言',
            'theme': '主题',
            'status': '状态：就绪',
            'start': '开始',
            'stop': '停止',
            'settings': '设置',
            'export': '导出数据',
            'import': '导入数据',
            'advanced': '高级选项',
            'reports': '生成报告',
            'network_map': '网络地图',
            'performance': '性能监控',
            'help': '帮助',
            'backup': '备份数据',
            'restore': '恢复数据',
            'clear_logs': '清除日志',
            'advanced_settings': '高级设置',
            'network_stats': '网络统计',
            'traffic_analysis': '流量分析',
            'schedule_scan': '计划扫描',
            'wake_on_lan': '网络唤醒',
            'port_scan': '端口扫描',
            'vulnerability_scan': '漏洞扫描',
            'firewall_rules': '防火墙规则',
            'snmp_monitor': 'SNMP监控',
            'dns_check': 'DNS检查',
            'export_pcap': '导出PCAP',
            'import_pcap': '导入PCAP'
        }
    }
    
    @staticmethod
    def get_text(lang, key):
        return LanguageManager.translations.get(lang, LanguageManager.translations['en']).get(key, key)

class DatabaseManager:
    def __init__(self, db_path='netbridge.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                details TEXT,
                severity TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configurations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                settings TEXT,
                created_at TEXT,
                modified_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                content TEXT,
                language TEXT,
                category TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                mac_address TEXT,
                device_name TEXT,
                last_seen TEXT,
                vendor TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                cpu_usage REAL,
                memory_usage REAL,
                network_usage REAL,
                packet_loss REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                port INTEGER,
                status TEXT,
                protocol TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                protocol TEXT,
                port_range TEXT,
                action TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                created_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device_ip TEXT,
                metric_name TEXT,
                value TEXT
            )
        ''')
        self.conn.commit()
    
    def save_log(self, event_type, details, severity='INFO'):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO network_logs (timestamp, event_type, details, severity) VALUES (?, ?, ?, ?)',
                     (datetime.datetime.now().isoformat(), event_type, details, severity))
        self.conn.commit()
    
    def save_config(self, name, settings):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO configurations (name, settings, created_at, modified_at) VALUES (?, ?, ?, ?)',
                     (name, json.dumps(settings), datetime.datetime.now().isoformat(), datetime.datetime.now().isoformat()))
        self.conn.commit()
    
    def update_config(self, config_id, name, settings):
        cursor = self.conn.cursor()
        cursor.execute('UPDATE configurations SET name = ?, settings = ?, modified_at = ? WHERE id = ?',
                     (name, json.dumps(settings), datetime.datetime.now().isoformat(), config_id))
        self.conn.commit()
    
    def load_configs(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, name, settings FROM configurations')
        return [(row[0], row[1], json.loads(row[2])) for row in cursor.fetchall()]
    
    def add_knowledge(self, title, content, language, category='General'):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO knowledge_base (title, content, language, category) VALUES (?, ?, ?, ?)',
                     (title, content, language, category))
        self.conn.commit()
    
    def get_knowledge(self, language, category=None):
        cursor = self.conn.cursor()
        if category:
            cursor.execute('SELECT title, content FROM knowledge_base WHERE language = ? AND category = ?', (language, category))
        else:
            cursor.execute('SELECT title, content FROM knowledge_base WHERE language = ?', (language,))
        return cursor.fetchall()
    
    def save_device(self, ip_address, mac_address, device_name, vendor='Unknown'):
        cursor = self.conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO network_devices (ip_address, mac_address, device_name, last_seen, vendor) VALUES (?, ?, ?, ?, ?)',
                     (ip_address, mac_address, device_name, datetime.datetime.now().isoformat(), vendor))
        self.conn.commit()
    
    def get_devices(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT ip_address, mac_address, device_name, last_seen, vendor FROM network_devices')
        return cursor.fetchall()
    
    def save_performance_metrics(self, cpu_usage, memory_usage, network_usage, packet_loss):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO performance_metrics (timestamp, cpu_usage, memory_usage, network_usage, packet_loss) VALUES (?, ?, ?, ?, ?)',
                     (datetime.datetime.now().isoformat(), cpu_usage, memory_usage, network_usage, packet_loss))
        self.conn.commit()
    
    def save_security_scan(self, port, status, protocol):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO security_scans (timestamp, port, status, protocol) VALUES (?, ?, ?, ?)',
                     (datetime.datetime.now().isoformat(), port, status, protocol))
        self.conn.commit()
    
    def save_firewall_rule(self, rule_name, protocol, port_range, action, source_ip, destination_ip):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO firewall_rules (rule_name, protocol, port_range, action, source_ip, destination_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (rule_name, protocol, port_range, action, source_ip, destination_ip, datetime.datetime.now().isoformat()))
        self.conn.commit()
    
    def get_firewall_rules(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT rule_name, protocol, port_range, action, source_ip, destination_ip FROM firewall_rules')
        return cursor.fetchall()
    
    def save_snmp_metric(self, device_ip, metric_name, value):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO snmp_metrics (timestamp, device_ip, metric_name, value) VALUES (?, ?, ?, ?)',
                     (datetime.datetime.now().isoformat(), device_ip, metric_name, str(value)))
        self.conn.commit()
    
    def get_snmp_metrics(self, device_ip=None):
        cursor = self.conn.cursor()
        if device_ip:
            cursor.execute('SELECT timestamp, metric_name, value FROM snmp_metrics WHERE device_ip = ?', (device_ip,))
        else:
            cursor.execute('SELECT timestamp, device_ip, metric_name, value FROM snmp_metrics')
        return cursor.fetchall()
    
    def clear_logs(self):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM network_logs')
        cursor.execute('DELETE FROM performance_metrics')
        cursor.execute('DELETE FROM security_scans')
        cursor.execute('DELETE FROM snmp_metrics')
        self.conn.commit()

class EncryptionManager:
    def __init__(self):
        self.key_file = 'encryption_key.key'
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data):
        return self.cipher.encrypt(json.dumps(data).encode())
    
    def decrypt_data(self, encrypted_data):
        try:
            return json.loads(self.cipher.decrypt(encrypted_data).decode())
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            return {}

class NetworkScanner(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    device_signal = pyqtSignal(str, str, str)
    
    def __init__(self, ip_range='192.168.1.0/24'):
        super().__init__()
        self.ip_range = ip_range
        self.running = False
    
    def run(self):
        self.running = True
        try:
            interfaces = psutil.net_if_addrs()
            total_interfaces = len(interfaces)
            for i, interface in enumerate(interfaces):
                if not self.running:
                    break
                stats = psutil.net_if_stats()[interface]
                self.update_signal.emit(f"Interface: {interface}\n")
                self.update_signal.emit(f"Status: {'Up' if stats.isup else 'Down'}\n")
                for addr in interfaces[interface]:
                    self.update_signal.emit(f"Address: {addr.address}\n")
                    self.update_signal.emit(f"Netmask: {addr.netmask}\n")
                self.progress_signal.emit(int((i + 1) / total_interfaces * 100))
                
                # ARP scan for network devices
                network = netaddr.IPNetwork(self.ip_range)
                total_ips = len(network)
                for j, ip in enumerate(network):
                    if not self.running:
                        break
                    arp = scapy.ARP(pdst=str(ip))
                    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether/arp
                    result = scapy.srp(packet, timeout=0.1, verbose=False)[0]
                    for sent, received in result:
                        vendor = self.get_vendor(received.hwsrc)
                        self.device_signal.emit(str(received.psrc), received.hwsrc, vendor)
                    self.progress_signal.emit(int((j + 1) / total_ips * 100))
                
                # Check router status
                try:
                    self.update_signal.emit(f"Checking router status for {interface}...\n")
                    router_info = self.get_router_info()
                    self.update_signal.emit(f"Router: {router_info}\n")
                except Exception as e:
                    self.update_signal.emit(f"Router check error: {str(e)}\n")
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}\n")
            logging.error(f"Scanner error: {str(e)}")
    
    def get_vendor(self, mac_address):
        try:
            # Simple MAC vendor lookup (replace with actual OUI database lookup if available)
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def get_router_info(self):
        try:
            # Use Windows-specific command to get default gateway
            if platform.system() == "Windows":
                result = subprocess.check_output("netsh interface ip show config", shell=True, text=True)
                for line in result.splitlines():
                    if "Default Gateway" in line:
                        gateway = line.split(":")[-1].strip()
                        return f"Default Gateway: {gateway}"
            else:
                # Fallback for non-Windows systems (though not used here)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    return f"Default Gateway: {s.getsockname()[0]}"
            return "Unknown"
        except Exception as e:
            logging.error(f"Router info error: {str(e)}")
            return "Unknown"

class NetworkSimulator:
    def __init__(self):
        self.packets = []
        self.simulation_running = False
        self.pcap_file = None
    
    def simulate_packet(self, src_ip, dst_ip, protocol='TCP', payload='', dport=80, sport=12345):
        try:
            packet = scapy.IP(src=src_ip, dst=dst_ip)
            if protocol == 'TCP':
                packet = packet/scapy.TCP(dport=dport, sport=sport)/payload
            elif protocol == 'UDP':
                packet = packet/scapy.UDP(dport=dport, sport=sport)/payload
            elif protocol == 'ICMP':
                packet = packet/scapy.ICMP()/payload
            elif protocol == 'DHCP':
                packet = packet/scapy.UDP(sport=68, dport=67)/scapy.BOOTP()/scapy.DHCP(options=[('message-type', 'discover')])
            elif protocol == 'DNS':
                packet = packet/scapy.UDP(sport=sport, dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=payload))
            self.packets.append(packet)
            if self.pcap_file:
                scapy.wrpcap(self.pcap_file, packet, append=True)
            return f"Simulated {protocol} packet from {src_ip} to {dst_ip} (dport: {dport}, sport: {sport}) with payload: {payload[:50]}..."
        except Exception as e:
            return f"Simulation error: {str(e)}"
    
    def simulate_network_traffic(self, src_ip, dst_ip, protocol, packet_count, dport=80, sport=12345):
        results = []
        for i in range(packet_count):
            if not self.simulation_running:
                break
            payload = f"Test packet {i+1}"
            result = self.simulate_packet(src_ip, dst_ip, protocol, payload, dport, sport)
            results.append(result)
            time.sleep(0.1)
        return results
    
    def simulate_dos_attack(self, target_ip, packet_count):
        results = []
        for i in range(packet_count):
            if not self.simulation_running:
                break
            packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=80, flags='S')
            self.packets.append(packet)
            if self.pcap_file:
                scapy.wrpcap(self.pcap_file, packet, append=True)
            results.append(f"Simulated SYN packet to {target_ip}")
            time.sleep(0.01)
        return results
    
    def start_pcap_recording(self, filename):
        self.pcap_file = filename
        if os.path.exists(filename):
            os.remove(filename)
    
    def stop_pcap_recording(self):
        self.pcap_file = None
    
    def replay_pcap(self, filename):
        try:
            packets = scapy.rdpcap(filename)
            results = []
            for packet in packets:
                if not self.simulation_running:
                    break
                self.packets.append(packet)
                results.append(f"Replayed packet: {packet.summary()}")
                time.sleep(0.01)
            return results
        except Exception as e:
            return [f"PCAP replay error: {str(e)}"]

class PerformanceMonitor(QThread):
    update_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = False
    
    def run(self):
        self.running = True
        while self.running:
            metrics = {
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent,
                'network': sum([x.bytes_sent + x.bytes_recv for x in psutil.net_io_counters(pernic=True).values()]),
                'packet_loss': self.calculate_packet_loss(),
                'disk_usage': psutil.disk_usage('/').percent,
                'active_connections': len(psutil.net_connections())
            }
            self.update_signal.emit(metrics)
            time.sleep(1)
    
    def calculate_packet_loss(self):
        try:
            return ping3.ping('8.8.8.8', timeout=1) or 0.0
        except:
            return 0.0

class ReportGenerator:
    @staticmethod
    def generate_html_report(logs, filename='report.html'):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetBridge Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .severity-info { background-color: #e6f3ff; }
                .severity-warning { background-color: #fff3cd; }
                .severity-error { background-color: #f8d7da; }
            </style>
        </head>
        <body>
            <h1>NetBridge Network Report</h1>
            <p>Generated: {}</p>
            <table>
                <tr><th>Timestamp</th><th>Event Type</th><th>Details</th><th>Severity</th></tr>
        """.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        for log in logs:
            html += f'<tr class="severity-{log[3].lower()}"><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td>{log[3]}</td></tr>'
        html += """
            </table>
        </body>
        </html>
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename
    
    @staticmethod
    def generate_pdf_report(logs, filename='report.pdf'):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
            
            doc = SimpleDocTemplate(filename, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            elements.append(Paragraph("NetBridge Network Report", styles['Title']))
            elements.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            
            data = [['Timestamp', 'Event Type', 'Details', 'Severity']] + list(logs)
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            doc.build(elements)
            return filename
        except ImportError:
            return None

class NetworkStatistics:
    def __init__(self):
        self.packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DHCP': 0, 'DNS': 0}
        self.traffic_volume = {'sent': 0, 'received': 0}
        self.connection_times = []
        self.bandwidth_usage = []
        self.protocol_distribution = {}
    
    def update_packet_count(self, protocol):
        if protocol in self.packet_counts:
            self.packet_counts[protocol] += 1
        self.protocol_distribution[protocol] = self.protocol_distribution.get(protocol, 0) + 1
    
    def update_traffic_volume(self, sent_bytes, received_bytes):
        self.traffic_volume['sent'] += sent_bytes
        self.traffic_volume['received'] += received_bytes
        self.bandwidth_usage.append({'timestamp': datetime.datetime.now().isoformat(), 'sent': sent_bytes, 'received': received_bytes})
    
    def add_connection_time(self, time_ms):
        self.connection_times.append(time_ms)
    
    def get_stats(self):
        return {
            'packet_counts': self.packet_counts,
            'traffic_volume': self.traffic_volume,
            'avg_connection_time': sum(self.connection_times) / len(self.connection_times) if self.connection_times else 0,
            'bandwidth_usage': self.bandwidth_usage[-100:],  # Keep last 100 data points
            'protocol_distribution': self.protocol_distribution
        }

class FirewallManager:
    def __init__(self):
        # Placeholder for Windows firewall management
        pass
    
    def add_rule(self, rule_name, protocol, port_range, action, source_ip, destination_ip):
        try:
            # Log the rule addition (actual Windows firewall implementation would use netsh or COM)
            logging.info(f"Adding firewall rule: {rule_name}, {protocol}, {port_range}, {action}, {source_ip}, {destination_ip}")
            # For Windows, you could use subprocess to run netsh commands, e.g.:
            # subprocess.run(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action={action.lower()} protocol={protocol} localport={port_range} remoteip={source_ip} remoteip={destination_ip}', shell=True)
            return True
        except Exception as e:
            logging.error(f"Firewall rule error: {str(e)}")
            return False
    
    def remove_rule(self, rule_name):
        try:
            # Log the rule removal
            logging.info(f"Removing firewall rule: {rule_name}")
            # For Windows, you could use:
            # subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True)
            return True
        except Exception as e:
            logging.error(f"Firewall rule removal error: {str(e)}")
            return False

class SNMPMonitor:
    def __init__(self):
        self.snmp_session = None
    
    def connect(self, ip, community='public'):
        try:
            self.snmp_session = snmp.Session(hostname=ip, community=community)
            return True
        except Exception as e:
            logging.error(f"SNMP connection error: {str(e)}")
            return False
    
    def get_metric(self, oid):
        try:
            return self.snmp_session.get(oid)
        except Exception as e:
            logging.error(f"SNMP metric error: {str(e)}")
            return None

class NetBridge(QMainWindow):
    def __init__(self):
        super().__init__()
        self.language = 'en'
        self.db = DatabaseManager()
        self.encryption = EncryptionManager()
        self.scanner = NetworkScanner()
        self.simulator = NetworkSimulator()
        self.performance_monitor = PerformanceMonitor()
        self.stats = NetworkStatistics()
        self.firewall = FirewallManager()
        self.snmp_monitor = SNMPMonitor()
        self.settings = QSettings('Hamid Yarali', 'NetBridge')
        
        # Set the window icon (favicon) and application icon
        icon_path = 'NetBridge.jpg'
        if os.path.exists(icon_path):
            try:
                icon = QIcon(icon_path)
                if not icon.isNull():  # Check if the icon loaded successfully
                    self.setWindowIcon(icon)
                    QApplication.instance().setWindowIcon(icon)
                else:
                    logging.warning(f"Failed to load icon from {icon_path}: Invalid image format")
                    # Fallback to default Qt icon
                    self.setWindowIcon(QIcon.fromTheme("network"))  # Example fallback
                    QApplication.instance().setWindowIcon(QIcon.fromTheme("network"))
            except Exception as e:
                logging.error(f"Error loading icon from {icon_path}: {str(e)}")
                # Fallback to default Qt icon
                self.setWindowIcon(QIcon.fromTheme("network"))
                QApplication.instance().setWindowIcon(QIcon.fromTheme("network"))
        else:
            logging.warning(f"Icon file {icon_path} not found")
            # Fallback to default Qt icon
            self.setWindowIcon(QIcon.fromTheme("network"))
            QApplication.instance().setWindowIcon(QIcon.fromTheme("network"))
        
        self.init_ui()
        self.init_knowledge_base()
        self.setup_menus()
        self.setup_toolbar()
        self.setup_status_bar()
        self.setup_performance_monitor()
        self.setup_schedule()
        self.load_settings()
    
    def init_ui(self):
        self.setWindowTitle(LanguageManager.get_text(self.language, 'title'))
        self.setGeometry(100, 100, 1600, 1000)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        
        # Splitter for resizable panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel (Network Map and Devices)
        left_panel = QDockWidget('Network Overview')
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        self.network_map = QTreeWidget()
        self.network_map.setHeaderLabels(['Device', 'IP', 'MAC', 'Last Seen', 'Vendor'])
        self.network_map.setColumnWidth(0, 200)
        self.network_map.setColumnWidth(1, 150)
        self.network_map.setColumnWidth(2, 150)
        left_layout.addWidget(QLabel(LanguageManager.get_text(self.language, 'network_map')))
        left_layout.addWidget(self.network_map)
        
        device_controls = QHBoxLayout()
        refresh_devices_button = QPushButton('Refresh Devices')
        refresh_devices_button.clicked.connect(self.update_network_map)
        device_controls.addWidget(refresh_devices_button)
        
        export_devices_button = QPushButton('Export Devices')
        export_devices_button.clicked.connect(self.export_devices)
        device_controls.addWidget(export_devices_button)
        
        wol_button = QPushButton(LanguageManager.get_text(self.language, 'wake_on_lan'))
        wol_button.clicked.connect(self.wake_on_lan)
        device_controls.addWidget(wol_button)
        
        left_layout.addLayout(device_controls)
        left_panel.setWidget(left_widget)
        splitter.addWidget(left_panel)
        
        # Right panel (Tabs)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        self.tabs = QTabWidget()
        right_layout.addWidget(self.tabs)
        
        # Diagnostics Tab
        diagnostics_widget = QWidget()
        diagnostics_layout = QVBoxLayout()
        diagnostics_widget.setLayout(diagnostics_layout)
        
        self.diagnostics_output = QTextEdit()
        self.diagnostics_output.setReadOnly(True)
        self.diagnostics_output.setFont(QFont('Courier', 10))
        diagnostics_layout.addWidget(self.diagnostics_output)
        
        diagnostics_controls = QHBoxLayout()
        scan_button = QPushButton(LanguageManager.get_text(self.language, 'scan'))
        scan_button.clicked.connect(self.start_scan)
        diagnostics_controls.addWidget(scan_button)
        
        self.ip_range_input = QLineEdit('192.168.1.0/24')
        diagnostics_controls.addWidget(QLabel('IP Range:'))
        diagnostics_controls.addWidget(self.ip_range_input)
        
        schedule_scan_button = QPushButton(LanguageManager.get_text(self.language, 'schedule_scan'))
        schedule_scan_button.clicked.connect(self.schedule_scan)
        diagnostics_controls.addWidget(schedule_scan_button)
        
        diagnostics_layout.addLayout(diagnostics_controls)
        
        self.diagnostics_progress = QProgressBar()
        diagnostics_layout.addWidget(self.diagnostics_progress)
        
        self.tabs.addTab(diagnostics_widget, LanguageManager.get_text(self.language, 'diagnostics'))
        
        # Optimizer Tab
        optimizer_widget = QWidget()
        optimizer_layout = QVBoxLayout()
        optimizer_widget.setLayout(optimizer_layout)
        
        optimizer_group = QGroupBox(LanguageManager.get_text(self.language, 'optimizer'))
        optimizer_form = QFormLayout()
        
        self.dns_input = QLineEdit('8.8.8.8')
        optimizer_form.addRow('Primary DNS:', self.dns_input)
        
        self.dns2_input = QLineEdit('8.8.4.4')
        optimizer_form.addRow('Secondary DNS:', self.dns2_input)
        
        self.wifi_channel = QSpinBox()
        self.wifi_channel.setRange(1, 13)
        optimizer_form.addRow('Wi-Fi Channel:', self.wifi_channel)
        
        self.qos_enabled = QCheckBox('Enable QoS')
        optimizer_form.addRow('QoS:', self.qos_enabled)
        
        self.mtu_size = QSpinBox()
        self.mtu_size.setRange(576, 1500)
        self.mtu_size.setValue(1500)
        optimizer_form.addRow('MTU Size:', self.mtu_size)
        
        self.tcp_window_size = QSpinBox()
        self.tcp_window_size.setRange(1024, 65535)
        self.tcp_window_size.setValue(65535)
        optimizer_form.addRow('TCP Window Size:', self.tcp_window_size)
        
        self.ipv6_enabled = QCheckBox('Enable IPv6')
        optimizer_form.addRow('IPv6 Support:', self.ipv6_enabled)
        
        self.wpa3_enabled = QCheckBox('Enable WPA3')
        optimizer_form.addRow('WPA3 Security:', self.wpa3_enabled)
        
        optimizer_group.setLayout(optimizer_form)
        optimizer_layout.addWidget(optimizer_group)
        
        optimize_button = QPushButton(LanguageManager.get_text(self.language, 'optimize'))
        optimize_button.clicked.connect(self.optimize_network)
        optimizer_layout.addWidget(optimize_button)
        
        self.optimizer_status = QLabel('Status: Idle')
        optimizer_layout.addWidget(self.optimizer_status)
        
        self.tabs.addTab(optimizer_widget, LanguageManager.get_text(self.language, 'optimizer'))
        
        # Simulator Tab
        simulator_widget = QWidget()
        simulator_layout = QVBoxLayout()
        simulator_widget.setLayout(simulator_layout)
        
        simulator_group = QGroupBox(LanguageManager.get_text(self.language, 'simulator'))
        simulator_form = QFormLayout()
        
        self.src_ip = QLineEdit('192.168.1.1')
        simulator_form.addRow('Source IP:', self.src_ip)
        
        self.dst_ip = QLineEdit('192.168.1.100')
        simulator_form.addRow('Destination IP:', self.dst_ip)
        
        self.protocol = QComboBox()
        self.protocol.addItems(['TCP', 'UDP', 'ICMP', 'DHCP', 'DNS'])
        simulator_form.addRow('Protocol:', self.protocol)
        
        self.packet_count = QSpinBox()
        self.packet_count.setRange(1, 1000)
        self.packet_count.setValue(10)
        simulator_form.addRow('Packet Count:', self.packet_count)
        
        self.dport_input = QSpinBox()
        self.dport_input.setRange(1, 65535)
        self.dport_input.setValue(80)
        simulator_form.addRow('Destination Port:', self.dport_input)
        
        self.sport_input = QSpinBox()
        self.sport_input.setRange(1, 65535)
        self.sport_input.setValue(12345)
        simulator_form.addRow('Source Port:', self.sport_input)
        
        self.payload_input = QLineEdit('Test payload')
        simulator_form.addRow('Payload:', self.payload_input)
        
        self.simulate_dos = QCheckBox('Simulate DoS Attack')
        simulator_form.addRow('DoS Simulation:', self.simulate_dos)
        
        self.latency_input = QSpinBox()
        self.latency_input.setRange(0, 1000)
        self.latency_input.setValue(0)
        simulator_form.addRow('Simulated Latency (ms):', self.latency_input)
        
        self.packet_loss_input = QSpinBox()
        self.packet_loss_input.setRange(0, 100)
        self.packet_loss_input.setValue(0)
        simulator_form.addRow('Packet Loss %:', self.packet_loss_input)
        
        simulator_group.setLayout(simulator_form)
        simulator_layout.addWidget(simulator_group)
        
        simulator_controls = QHBoxLayout()
        simulate_button = QPushButton(LanguageManager.get_text(self.language, 'simulate'))
        simulate_button.clicked.connect(self.start_simulation)
        simulator_controls.addWidget(simulate_button)
        
        stop_simulate_button = QPushButton(LanguageManager.get_text(self.language, 'stop'))
        stop_simulate_button.clicked.connect(self.stop_simulation)
        simulator_controls.addWidget(stop_simulate_button)
        
        pcap_record_button = QPushButton('Start PCAP Recording')
        pcap_record_button.clicked.connect(self.start_pcap_recording)
        simulator_controls.addWidget(pcap_record_button)
        
        pcap_stop_button = QPushButton('Stop PCAP Recording')
        pcap_stop_button.clicked.connect(self.stop_pcap_recording)
        simulator_controls.addWidget(pcap_stop_button)
        
        pcap_replay_button = QPushButton(LanguageManager.get_text(self.language, 'import_pcap'))
        pcap_replay_button.clicked.connect(self.replay_pcap)
        simulator_controls.addWidget(pcap_replay_button)
        
        simulator_layout.addLayout(simulator_controls)
        
        self.simulator_output = QTextEdit()
        self.simulator_output.setReadOnly(True)
        self.simulator_output.setFont(QFont('Courier', 10))
        simulator_layout.addWidget(self.simulator_output)
        
        self.tabs.addTab(simulator_widget, LanguageManager.get_text(self.language, 'simulator'))
        
        # Knowledge Base Tab
        knowledge_widget = QWidget()
        knowledge_layout = QVBoxLayout()
        knowledge_widget.setLayout(knowledge_layout)
        
        knowledge_controls = QHBoxLayout()
        self.knowledge_category = QComboBox()
        self.knowledge_category.addItems(['General', 'Troubleshooting', 'Security', 'Configuration', 'Advanced'])
        knowledge_controls.addWidget(QLabel('Category:'))
        knowledge_controls.addWidget(self.knowledge_category)
        
        add_knowledge_button = QPushButton('Add Knowledge')
        add_knowledge_button.clicked.connect(self.add_knowledge_item)
        knowledge_controls.addWidget(add_knowledge_button)
        
        export_knowledge_button = QPushButton('Export Knowledge')
        export_knowledge_button.clicked.connect(self.export_knowledge)
        knowledge_controls.addWidget(export_knowledge_button)
        
        knowledge_layout.addLayout(knowledge_controls)
        
        self.knowledge_table = QTableWidget()
        self.knowledge_table.setColumnCount(2)
        self.knowledge_table.setHorizontalHeaderLabels(['Title', 'Content'])
        self.knowledge_table.setColumnWidth(0, 200)
        self.knowledge_table.setColumnWidth(1, 400)
        knowledge_layout.addWidget(self.knowledge_table)
        
        self.tabs.addTab(knowledge_widget, LanguageManager.get_text(self.language, 'knowledge'))
        
        # Configuration Manager Tab
        config_widget = QWidget()
        config_layout = QVBoxLayout()
        config_widget.setLayout(config_layout)
        
        config_form = QFormLayout()
        self.config_name = QLineEdit()
        config_form.addRow('Configuration Name:', self.config_name)
        
        config_layout.addLayout(config_form)
        
        config_controls = QHBoxLayout()
        save_config_button = QPushButton(LanguageManager.get_text(self.language, 'save_config'))
        save_config_button.clicked.connect(self.save_configuration)
        config_controls.addWidget(save_config_button)
        
        load_config_button = QPushButton(LanguageManager.get_text(self.language, 'load_config'))
        load_config_button.clicked.connect(self.load_configuration)
        config_controls.addWidget(load_config_button)
        
        export_config_button = QPushButton(LanguageManager.get_text(self.language, 'export'))
        export_config_button.clicked.connect(self.export_configuration)
        config_controls.addWidget(export_config_button)
        
        import_config_button = QPushButton(LanguageManager.get_text(self.language, 'import'))
        import_config_button.clicked.connect(self.import_configuration)
        config_controls.addWidget(import_config_button)
        
        config_layout.addLayout(config_controls)
        
        self.config_table = QTableWidget()
        self.config_table.setColumnCount(3)
        self.config_table.setHorizontalHeaderLabels(['ID', 'Name', 'Settings'])
        self.config_table.setColumnWidth(0, 100)
        self.config_table.setColumnWidth(1, 200)
        self.config_table.setColumnWidth(2, 400)
        config_layout.addWidget(self.config_table)
        
        self.tabs.addTab(config_widget, LanguageManager.get_text(self.language, 'config'))
        
        # Security Analyzer Tab
        security_widget = QWidget()
        security_layout = QVBoxLayout()
        security_widget.setLayout(security_layout)
        
        self.security_output = QTextEdit()
        self.security_output.setReadOnly(True)
        self.security_output.setFont(QFont('Courier', 10))
        security_layout.addWidget(self.security_output)
        
        security_controls = QHBoxLayout()
        scan_security_button = QPushButton(LanguageManager.get_text(self.language, 'port_scan'))
        scan_security_button.clicked.connect(self.scan_security)
        security_controls.addWidget(scan_security_button)
        
        vulnerability_scan_button = QPushButton(LanguageManager.get_text(self.language, 'vulnerability_scan'))
        vulnerability_scan_button.clicked.connect(self.scan_vulnerabilities)
        security_controls.addWidget(vulnerability_scan_button)
        
        export_security_button = QPushButton('Export Security Report')
        export_security_button.clicked.connect(self.export_security_report)
        security_controls.addWidget(export_security_button)
        
        firewall_button = QPushButton(LanguageManager.get_text(self.language, 'firewall_rules'))
        firewall_button.clicked.connect(self.manage_firewall_rules)
        security_controls.addWidget(firewall_button)
        
        security_layout.addLayout(security_controls)
        
        self.security_graph = FigureCanvas(plt.Figure())
        security_layout.addWidget(self.security_graph)
        
        self.tabs.addTab(security_widget, LanguageManager.get_text(self.language, 'security'))
        
        # Log Analyzer Tab
        logs_widget = QWidget()
        logs_layout = QVBoxLayout()
        logs_widget.setLayout(logs_layout)
        
        self.logs_output = QTextEdit()
        self.logs_output.setReadOnly(True)
        self.logs_output.setFont(QFont('Courier', 10))
        logs_layout.addWidget(self.logs_output)
        
        logs_controls = QHBoxLayout()
        analyze_logs_button = QPushButton('Analyze Logs')
        analyze_logs_button.clicked.connect(self.analyze_logs)
        logs_controls.addWidget(analyze_logs_button)
        
        export_logs_button = QPushButton(LanguageManager.get_text(self.language, 'export'))
        export_logs_button.clicked.connect(self.export_logs)
        logs_controls.addWidget(export_logs_button)
        
        clear_logs_button = QPushButton(LanguageManager.get_text(self.language, 'clear_logs'))
        clear_logs_button.clicked.connect(self.clear_logs)
        logs_controls.addWidget(clear_logs_button)
        
        logs_layout.addLayout(logs_controls)
        
        self.logs_graph = FigureCanvas(plt.Figure())
        logs_layout.addWidget(self.logs_graph)
        
        self.tabs.addTab(logs_widget, LanguageManager.get_text(self.language, 'logs'))
        
        # Performance Monitor Tab
        performance_widget = QWidget()
        performance_layout = QVBoxLayout()
        performance_widget.setLayout(performance_layout)
        
        self.performance_output = QTextEdit()
        self.performance_output.setReadOnly(True)
        self.performance_output.setFont(QFont('Courier', 10))
        performance_layout.addWidget(self.performance_output)
        
        self.performance_graph = FigureCanvas(plt.Figure())
        performance_layout.addWidget(self.performance_graph)
        
        performance_controls = QHBoxLayout()
        start_monitor_button = QPushButton(LanguageManager.get_text(self.language, 'start'))
        start_monitor_button.clicked.connect(self.start_performance_monitor)
        performance_controls.addWidget(start_monitor_button)
        
        stop_monitor_button = QPushButton(LanguageManager.get_text(self.language, 'stop'))
        stop_monitor_button.clicked.connect(self.stop_performance_monitor)
        performance_controls.addWidget(stop_monitor_button)
        
        export_performance_button = QPushButton('Export Performance Data')
        export_performance_button.clicked.connect(self.export_performance_data)
        performance_controls.addWidget(export_performance_button)
        
        performance_layout.addLayout(performance_controls)
        
        self.tabs.addTab(performance_widget, LanguageManager.get_text(self.language, 'performance'))
        
        # Statistics Tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout()
        stats_widget.setLayout(stats_layout)
        
        self.stats_output = QTextEdit()
        self.stats_output.setReadOnly(True)
        self.stats_output.setFont(QFont('Courier', 10))
        stats_layout.addWidget(self.stats_output)
        
        stats_controls = QHBoxLayout()
        update_stats_button = QPushButton('Update Statistics')
        update_stats_button.clicked.connect(self.update_statistics)
        stats_controls.addWidget(update_stats_button)
        
        export_stats_button = QPushButton('Export Statistics')
        export_stats_button.clicked.connect(self.export_statistics)
        stats_controls.addWidget(export_stats_button)
        
        stats_layout.addLayout(stats_controls)
        
        self.stats_graph = FigureCanvas(plt.Figure())
        stats_layout.addWidget(self.stats_graph)
        
        self.tabs.addTab(stats_widget, LanguageManager.get_text(self.language, 'network_stats'))
        
        # Traffic Analysis Tab
        traffic_widget = QWidget()
        traffic_layout = QVBoxLayout()
        traffic_widget.setLayout(traffic_layout)
        
        self.traffic_output = QTextEdit()
        self.traffic_output.setReadOnly(True)
        self.traffic_output.setFont(QFont('Courier', 10))
        traffic_layout.addWidget(self.traffic_output)
        
        traffic_controls = QHBoxLayout()
        analyze_traffic_button = QPushButton('Analyze Traffic')
        analyze_traffic_button.clicked.connect(self.analyze_traffic)
        traffic_controls.addWidget(analyze_traffic_button)
        
        export_traffic_button = QPushButton('Export Traffic Data')
        export_traffic_button.clicked.connect(self.export_traffic_data)
        traffic_controls.addWidget(export_traffic_button)
        
        traffic_layout.addLayout(traffic_controls)
        
        self.traffic_graph = FigureCanvas(plt.Figure())
        traffic_layout.addWidget(self.traffic_graph)
        
        self.tabs.addTab(traffic_widget, LanguageManager.get_text(self.language, 'traffic_analysis'))
        
        # SNMP Monitor Tab
        snmp_widget = QWidget()
        snmp_layout = QVBoxLayout()
        snmp_widget.setLayout(snmp_layout)
        
        self.snmp_output = QTextEdit()
        self.snmp_output.setReadOnly(True)
        self.snmp_output.setFont(QFont('Courier', 10))
        snmp_layout.addWidget(self.snmp_output)
        
        snmp_controls = QHBoxLayout()
        self.snmp_ip = QLineEdit('192.168.1.1')
        snmp_controls.addWidget(QLabel('Device IP:'))
        snmp_controls.addWidget(self.snmp_ip)
        
        self.snmp_community = QLineEdit('public')
        snmp_controls.addWidget(QLabel('Community String:'))
        snmp_controls.addWidget(self.snmp_community)
        
        start_snmp_button = QPushButton(LanguageManager.get_text(self.language, 'snmp_monitor'))
        start_snmp_button.clicked.connect(self.start_snmp_monitor)
        snmp_controls.addWidget(start_snmp_button)
        
        snmp_layout.addLayout(snmp_controls)
        
        self.snmp_graph = FigureCanvas(plt.Figure())
        snmp_layout.addWidget(self.snmp_graph)
        
        self.tabs.addTab(snmp_widget, 'SNMP Monitor')
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 1200])
        
        # Connect signals
        self.scanner.update_signal.connect(self.update_diagnostics)
        self.scanner.progress_signal.connect(self.diagnostics_progress.setValue)
        self.scanner.device_signal.connect(self.update_device)
        self.performance_monitor.update_signal.connect(self.update_performance)
        self.knowledge_category.currentTextChanged.connect(self.update_knowledge_base)
    
    def setup_menus(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        
        export_action = QAction(LanguageManager.get_text(self.language, 'export'), self)
        export_action.setIcon(QIcon('export.png'))
        export_action.triggered.connect(self.export_all_data)
        file_menu.addAction(export_action)
        
        import_action = QAction(LanguageManager.get_text(self.language, 'import'), self)
        import_action.setIcon(QIcon('import.png'))
        import_action.triggered.connect(self.import_all_data)
        file_menu.addAction(import_action)
        
        backup_action = QAction(LanguageManager.get_text(self.language, 'backup'), self)
        backup_action.setIcon(QIcon('backup.png'))
        backup_action.triggered.connect(self.backup_data)
        file_menu.addAction(backup_action)
        
        restore_action = QAction(LanguageManager.get_text(self.language, 'restore'), self)
        restore_action.setIcon(QIcon('restore.png'))
        restore_action.triggered.connect(self.restore_data)
        file_menu.addAction(restore_action)
        
        settings_menu = menubar.addMenu(LanguageManager.get_text(self.language, 'settings'))
        
        language_menu = QMenu(LanguageManager.get_text(self.language, 'language'), self)
        settings_menu.addMenu(language_menu)
        
        for lang in ['en', 'fa', 'zh']:
            action = QAction(lang.upper(), self)
            action.triggered.connect(lambda checked, l=lang: self.change_language(l))
            language_menu.addAction(action)
        
        theme_menu = QMenu(LanguageManager.get_text(self.language, 'theme'), self)
        settings_menu.addMenu(theme_menu)
        
        windows11_action = QAction('Windows 11', self)
        windows11_action.triggered.connect(lambda: self.apply_theme('windows11'))
        theme_menu.addAction(windows11_action)
        
        dark_action = QAction('Dark', self)
        dark_action.triggered.connect(lambda: self.apply_theme('dark'))
        theme_menu.addAction(dark_action)
        
        red_blue_action = QAction('Red-Blue', self)
        red_blue_action.triggered.connect(lambda: self.apply_theme('red_blue'))
        theme_menu.addAction(red_blue_action)
        
        default_action = QAction('Default', self)
        default_action.triggered.connect(lambda: self.apply_theme('default'))
        theme_menu.addAction(default_action)
        
        advanced_settings_action = QAction(LanguageManager.get_text(self.language, 'advanced_settings'), self)
        advanced_settings_action.triggered.connect(self.show_advanced_settings)
        settings_menu.addAction(advanced_settings_action)
        
        help_menu = menubar.addMenu(LanguageManager.get_text(self.language, 'help'))
        help_action = QAction('Documentation', self)
        help_action.setIcon(QIcon('help.png'))
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
    
    def setup_toolbar(self):
        toolbar = QToolBar('Main Toolbar')
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)
        
        scan_action = QAction(QIcon('scan.png'), 'Scan', self)
        scan_action.triggered.connect(self.start_scan)
        toolbar.addAction(scan_action)
        
        optimize_action = QAction(QIcon('optimize.png'), 'Optimize', self)
        optimize_action.triggered.connect(self.optimize_network)
        toolbar.addAction(optimize_action)
        
        simulate_action = QAction(QIcon('simulate.png'), 'Simulate', self)
        simulate_action.triggered.connect(self.start_simulation)
        toolbar.addAction(simulate_action)
        
        stats_action = QAction(QIcon('stats.png'), 'Statistics', self)
        stats_action.triggered.connect(self.update_statistics)
        toolbar.addAction(stats_action)
        
        security_action = QAction(QIcon('security.png'), 'Security Scan', self)
        security_action.triggered.connect(self.scan_security)
        toolbar.addAction(security_action)
        
        wol_action = QAction(QIcon('wol.png'), 'Wake on LAN', self)
        wol_action.triggered.connect(self.wake_on_lan)
        toolbar.addAction(wol_action)
    
    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(LanguageManager.get_text(self.language, 'status'))
    
    def setup_performance_monitor(self):
        self.performance_data = {'cpu': [], 'memory': [], 'network': [], 'packet_loss': [], 'disk_usage': [], 'active_connections': []}
        self.performance_timestamps = []
    
    def setup_schedule(self):
        self.scheduler = schedule.Scheduler()
        self.schedule_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.schedule_thread.start()
    
    def run_scheduler(self):
        while True:
            self.scheduler.run_pending()
            time.sleep(1)
    
    def load_settings(self):
        self.language = self.settings.value('language', 'en')
        self.apply_theme(self.settings.value('theme', 'windows11'))
        self.change_language(self.language)
    
    def init_knowledge_base(self):
        knowledge_items = [
            ('Network Setup Guide', 'Step-by-step guide to configure your router, including IP settings, DNS configuration, and Wi-Fi channel selection.', 'en', 'General'),
            ('Wi-Fi Troubleshooting', 'Common Wi-Fi issues and solutions, including interference mitigation and channel optimization.', 'en', 'Troubleshooting'),
            ('Network Security Basics', 'Best practices for securing your network, including strong passwords and encryption.', 'en', 'Security'),
            ('Router Configuration', 'Guide to configure router settings for optimal performance.', 'en', 'Configuration'),
            ('Advanced Network Analysis', 'Techniques for deep packet inspection and traffic analysis.', 'en', 'Advanced'),
            ('راهنمای تنظیم شبکه', 'راهنمای گام به گام برای پیکربندی روتر، شامل تنظیمات IP، پیکربندی DNS و انتخاب کانال وای‌فای.', 'fa', 'General'),
            ('عیب‌یابی وای‌فای', 'مشکلات رایج وای‌فای و راه‌حل‌ها، شامل کاهش تداخل و بهینه‌سازی کانال.', 'fa', 'Troubleshooting'),
            ('اصول امنیت شبکه', 'بهترین روش‌ها برای ایمن‌سازی شبکه، شامل رمزهای قوی و رمزنگاری.', 'fa', 'Security'),
            ('پیکربندی روتر', 'راهنمای پیکربندی تنظیمات روتر برای عملکرد بهینه.', 'fa', 'Configuration'),
            ('تحلیل پیشرفته شبکه', 'تکنیک‌های بازرسی عمیق بسته‌ها و تحلیل ترافیک.', 'fa', 'Advanced'),
            ('网络设置指南', '配置路由器的分步指南，包括IP设置、DNS配置和Wi-Fi频道选择。', 'zh', 'General'),
            ('Wi-Fi故障排除', '常见的Wi-Fi问题及解决方案，包括干扰缓解和频道优化。', 'zh', 'Troubleshooting'),
            ('网络安全基础', '保护网络的最佳实践，包括强密码和加密。', 'zh', 'Security'),
            ('路由器配置', '配置路由器设置以获得最佳性能的指南。', 'zh', 'Configuration'),
            ('高级网络分析', '深度数据包检查和流量分析技术。', 'zh', 'Advanced'),
            ('Firewall Configuration', 'Guide to setting up and managing firewall rules for network security.', 'en', 'Security'),
            ('SNMP Monitoring', 'How to configure and use SNMP for network monitoring.', 'en', 'Advanced'),
            ('VLAN Setup', 'Guide to configuring Virtual LANs for network segmentation.', 'en', 'Configuration'),
            ('تنظیم فایروال', 'راهنمای تنظیم و مدیریت قوانین فایروال برای امنیت شبکه.', 'fa', 'Security'),
            ('نظارت SNMP', 'چگونه SNMP را برای نظارت بر شبکه پیکربندی و استفاده کنیم.', 'fa', 'Advanced'),
            ('تنظیم VLAN', 'راهنمای پیکربندی شبکه‌های مجازی برای تقسیم‌بندی شبکه.', 'fa', 'Configuration'),
            ('防火墙配置', '设置和管理防火墙规则以确保网络安全的指南。', 'zh', 'Security'),
            ('SNMP监控', '如何配置和使用SNMP进行网络监控。', 'zh', 'Advanced'),
            ('VLAN设置', '配置虚拟局域网以进行网络分段的指南。', 'zh', 'Configuration')
        ]
        for title, content, lang, category in knowledge_items:
            self.db.add_knowledge(title, content, lang, category)
        self.update_knowledge_base()
    
    def change_language(self, lang):
        self.language = lang
        self.settings.setValue('language', lang)
        self.update_ui_texts()
        self.update_knowledge_base()
        self.set_layout_direction(lang)
    
    def set_layout_direction(self, lang):
        if lang == 'fa':
            self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        else:
            self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    
    def apply_theme(self, theme):
        self.settings.setValue('theme', theme)
        if theme == 'windows11':
            ThemeManager.apply_windows11_theme(QApplication.instance())
        elif theme == 'dark':
            ThemeManager.apply_dark_theme(QApplication.instance())
        elif theme == 'red_blue':
            ThemeManager.apply_red_blue_theme(QApplication.instance())
        else:
            ThemeManager.apply_default_theme(QApplication.instance())
    
    def update_ui_texts(self):
        self.setWindowTitle(LanguageManager.get_text(self.language, 'title'))
        self.tabs.setTabText(0, LanguageManager.get_text(self.language, 'diagnostics'))
        self.tabs.setTabText(1, LanguageManager.get_text(self.language, 'optimizer'))
        self.tabs.setTabText(2, LanguageManager.get_text(self.language, 'simulator'))
        self.tabs.setTabText(3, LanguageManager.get_text(self.language, 'knowledge'))
        self.tabs.setTabText(4, LanguageManager.get_text(self.language, 'config'))
        self.tabs.setTabText(5, LanguageManager.get_text(self.language, 'security'))
        self.tabs.setTabText(6, LanguageManager.get_text(self.language, 'logs'))
        self.tabs.setTabText(7, LanguageManager.get_text(self.language, 'performance'))
        self.tabs.setTabText(8, LanguageManager.get_text(self.language, 'network_stats'))
        self.tabs.setTabText(9, LanguageManager.get_text(self.language, 'traffic_analysis'))
        self.status_bar.showMessage(LanguageManager.get_text(self.language, 'status'))
    
    def start_scan(self):
        self.diagnostics_output.clear()
        self.diagnostics_progress.setValue(0)
        self.scanner.ip_range = self.ip_range_input.text()
        try:
            netaddr.IPNetwork(self.scanner.ip_range)  # Validate IP range
            self.scanner.start()
            self.status_bar.showMessage('Scanning network...')
            self.db.save_log('network_scan', f"Started scanning {self.scanner.ip_range}", 'INFO')
        except ValueError as e:
            self.diagnostics_output.append(f"Invalid IP range: {str(e)}")
            self.db.save_log('scan_error', str(e), 'ERROR')
            self.status_bar.showMessage('Invalid IP range')
    
    def update_diagnostics(self, text):
        self.diagnostics_output.append(text)
        self.db.save_log('scan', text)
    
    def update_device(self, ip, mac, vendor):
        self.db.save_device(ip, mac, f'Device_{ip}', vendor)
        self.update_network_map()
    
    def update_network_map(self):
        self.network_map.clear()
        devices = self.db.get_devices()
        for ip, mac, name, last_seen, vendor in devices:
            item = QTreeWidgetItem(self.network_map)
            item.setText(0, name)
            item.setText(1, ip)
            item.setText(2, mac)
            item.setText(3, last_seen)
            item.setText(4, vendor)
    
    def export_devices(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Devices', '', 'CSV Files (*.csv)')
        if filename:
            devices = self.db.get_devices()
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'MAC Address', 'Device Name', 'Last Seen', 'Vendor'])
                writer.writerows(devices)
            self.status_bar.showMessage('Devices exported')
            self.db.save_log('export_devices', f"Exported devices to {filename}", 'INFO')
    
    def wake_on_lan(self):
        ip, ok = QInputDialog.getText(self, 'Wake on LAN', 'Enter MAC Address:')
        if ok and ip:
            try:
                wakeonlan.send_magic_packet(ip)
                self.status_bar.showMessage(f'Sent Wake-on-LAN packet to {ip}')
                self.db.save_log('wake_on_lan', f"Sent WOL to {ip}", 'INFO')
            except Exception as e:
                self.status_bar.showMessage(f'WOL failed: {str(e)}')
                self.db.save_log('wake_on_lan_error', str(e), 'ERROR')
    
    def optimize_network(self):
        try:
            settings = {
                'dns': self.dns_input.text(),
                'dns2': self.dns2_input.text(),
                'wifi_channel': self.wifi_channel.value(),
                'qos': self.qos_enabled.isChecked(),
                'mtu': self.mtu_size.value(),
                'tcp_window_size': self.tcp_window_size.value(),
                'ipv6': self.ipv6_enabled.isChecked(),
                'wpa3': self.wpa3_enabled.isChecked()
            }
            
            # Validate DNS addresses
            for dns in [settings['dns'], settings['dns2']]:
                if dns:
                    ipaddress.ip_address(dns)
            
            # Apply settings (simplified - actual implementation depends on OS)
            self.apply_network_settings(settings)
            
            encrypted_settings = self.encryption.encrypt_data(settings)
            self.db.save_config('Network Settings', settings)
            self.diagnostics_output.append(f"Optimized network with settings: {settings}")
            self.optimizer_status.setText('Status: Optimization complete')
            self.db.save_log('optimization', str(settings), 'INFO')
            self.status_bar.showMessage('Network optimization complete')
        except ValueError as e:
            self.diagnostics_output.append(f"Invalid DNS address: {str(e)}")
            self.db.save_log('optimization_error', str(e), 'ERROR')
            self.status_bar.showMessage('Optimization failed')
        except Exception as e:
            self.diagnostics_output.append(f"Optimization error: {str(e)}")
            self.db.save_log('optimization_error', str(e), 'ERROR')
            self.status_bar.showMessage('Optimization failed')
    
    def apply_network_settings(self, settings):
        # Simplified implementation - actual OS-specific configuration needed
        logging.info(f"Applying network settings: {settings}")
        # Example: Apply DNS settings
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [settings['dns'], settings['dns2']]
            logging.info("DNS settings applied")
        except Exception as e:
            logging.error(f"DNS setting error: {str(e)}")
    
    def start_simulation(self):
        self.simulator.simulation_running = True
        if self.simulate_dos.isChecked():
            results = self.simulator.simulate_dos_attack(self.dst_ip.text(), self.packet_count.value())
        else:
            results = self.simulator.simulate_network_traffic(
                self.src_ip.text(),
                self.dst_ip.text(),
                self.protocol.currentText(),
                self.packet_count.value(),
                self.dport_input.value(),
                self.sport_input.value()
            )
        for result in results:
            self.simulator_output.append(result)
            self.db.save_log('simulation', result, 'INFO')
            self.stats.update_packet_count(self.protocol.currentText())
        self.status_bar.showMessage('Simulation complete')
    
    def stop_simulation(self):
        self.simulator.simulation_running = False
        self.simulator_output.append('Simulation stopped')
        self.db.save_log('simulation_stop', 'Simulation stopped', 'INFO')
        self.status_bar.showMessage('Simulation stopped')
    
    def start_pcap_recording(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save PCAP File', '', 'PCAP Files (*.pcap)')
        if filename:
            self.simulator.start_pcap_recording(filename)
            self.status_bar.showMessage('PCAP recording started')
            self.db.save_log('pcap_record', f"Started PCAP recording to {filename}", 'INFO')
    
    def stop_pcap_recording(self):
        self.simulator.stop_pcap_recording()
        self.status_bar.showMessage('PCAP recording stopped')
        self.db.save_log('pcap_record_stop', 'Stopped PCAP recording', 'INFO')
    
    def replay_pcap(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open PCAP File', '', 'PCAP Files (*.pcap)')
        if filename:
            results = self.simulator.replay_pcap(filename)
            for result in results:
                self.simulator_output.append(result)
                self.db.save_log('pcap_replay', result, 'INFO')
            self.status_bar.showMessage('PCAP replay complete')
    
    def update_knowledge_base(self):
        self.knowledge_table.setRowCount(0)
        category = self.knowledge_category.currentText()
        items = self.db.get_knowledge(self.language, category)
        self.knowledge_table.setRowCount(len(items))
        for row, (title, content) in enumerate(items):
            self.knowledge_table.setItem(row, 0, QTableWidgetItem(title))
            self.knowledge_table.setItem(row, 1, QTableWidgetItem(content))
    
    def add_knowledge_item(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Add Knowledge Item')
        layout = QFormLayout()
        
        title_input = QLineEdit()
        layout.addRow('Title:', title_input)
        
        content_input = QTextEdit()
        layout.addRow('Content:', content_input)
        
        category_input = QComboBox()
        category_input.addItems(['General', 'Troubleshooting', 'Security', 'Configuration', 'Advanced'])
        layout.addRow('Category:', category_input)
        
        buttons = QHBoxLayout()
        save_button = QPushButton('Save')
        save_button.clicked.connect(lambda: self.save_knowledge_item(title_input.text(), content_input.toPlainText(), category_input.currentText(), dialog))
        buttons.addWidget(save_button)
        
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        
        layout.addRow(buttons)
        dialog.setLayout(layout)
        dialog.resize(500, 400)
        dialog.exec()
    
    def save_knowledge_item(self, title, content, category, dialog):
        if title and content:
            self.db.add_knowledge(title, content, self.language, category)
            self.update_knowledge_base()
            dialog.accept()
            self.status_bar.showMessage('Knowledge item added')
            self.db.save_log('knowledge_add', f"Added knowledge item: {title}", 'INFO')
    
    def export_knowledge(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Knowledge', '', 'JSON Files (*.json)')
        if filename:
            items = self.db.get_knowledge(self.language)
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([{'title': title, 'content': content} for title, content in items], f, indent=2, ensure_ascii=False)
            self.status_bar.showMessage('Knowledge base exported')
            self.db.save_log('knowledge_export', f"Exported knowledge to {filename}", 'INFO')
    
    def save_configuration(self):
        settings = {
            'dns': self.dns_input.text(),
            'dns2': self.dns2_input.text(),
            'wifi_channel': self.wifi_channel.value(),
            'qos': self.qos_enabled.isChecked(),
            'mtu': self.mtu_size.value(),
            'tcp_window_size': self.tcp_window_size.value(),
            'ipv6': self.ipv6_enabled.isChecked(),
            'wpa3': self.wpa3_enabled.isChecked()
        }
        name = self.config_name.text() or f"Config_{datetime.datetime.now().isoformat()}"
        self.db.save_config(name, settings)
        self.update_config_table()
        self.status_bar.showMessage('Configuration saved')
        self.db.save_log('config_save', f"Saved configuration: {name}", 'INFO')
    
    def load_configuration(self):
        configs = self.db.load_configs()
        if configs:
            config_id, name, settings = configs[-1]
            self.dns_input.setText(settings.get('dns', ''))
            self.dns2_input.setText(settings.get('dns2', ''))
            self.wifi_channel.setValue(settings.get('wifi_channel', 1))
            self.qos_enabled.setChecked(settings.get('qos', False))
            self.mtu_size.setValue(settings.get('mtu', 1500))
            self.tcp_window_size.setValue(settings.get('tcp_window_size', 65535))
            self.ipv6_enabled.setChecked(settings.get('ipv6', False))
            self.wpa3_enabled.setChecked(settings.get('wpa3', False))
            self.diagnostics_output.append(f"Loaded configuration: {name}")
            self.status_bar.showMessage(f'Loaded configuration: {name}')
            self.db.save_log('config_load', f"Loaded configuration: {name}", 'INFO')
    
    def update_config_table(self):
        self.config_table.setRowCount(0)
        configs = self.db.load_configs()
        self.config_table.setRowCount(len(configs))
        for row, (config_id, name, settings) in enumerate(configs):
            self.config_table.setItem(row, 0, QTableWidgetItem(str(config_id)))
            self.config_table.setItem(row, 1, QTableWidgetItem(name))
            self.config_table.setItem(row, 2, QTableWidgetItem(str(settings)))
    
    def export_configuration(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Configuration', '', 'JSON Files (*.json)')
        if filename:
            configs = self.db.load_configs()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([{'id': c[0], 'name': c[1], 'settings': c[2]} for c in configs], f, indent=2)
            self.status_bar.showMessage('Configuration exported')
            self.db.save_log('config_export', f"Exported configuration to {filename}", 'INFO')
    
    def import_configuration(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Import Configuration', '', 'JSON Files (*.json)')
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    configs = json.load(f)
                for config in configs:
                    self.db.save_config(config['name'], config['settings'])
                self.update_config_table()
                self.status_bar.showMessage('Configuration imported')
                self.db.save_log('config_import', f"Imported configuration from {filename}", 'INFO')
            except Exception as e:
                self.status_bar.showMessage(f'Import failed: {str(e)}')
                self.db.save_log('config_import_error', str(e), 'ERROR')

    def scan_security(self):
        self.security_output.clear()
        ip = self.ip_range_input.text().split('/')[0]
        ports = [22, 80, 443, 3389]  # Common ports
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                status = 'open' if result == 0 else 'closed'
                self.security_output.append(f"Port {port}: {status}")
                self.db.save_security_scan(port, status, 'TCP')
                self.db.save_log('port_scan', f"Port {port} on {ip}: {status}", 'INFO')
                sock.close()
            except Exception as e:
                self.security_output.append(f"Port {port} scan error: {str(e)}")
                self.db.save_log('port_scan_error', str(e), 'ERROR')
        self.update_security_graph()
        self.status_bar.showMessage('Security scan complete')

    def scan_vulnerabilities(self):
        self.security_output.clear()
        ip = self.ip_range_input.text().split('/')[0]
        try:
            # Placeholder for vulnerability scanning (requires external service or database)
            self.security_output.append(f"Scanning {ip} for vulnerabilities...")
            # Example: Check for common vulnerabilities (simulated)
            vulnerabilities = ['Weak Passwords', 'Outdated Firmware']
            for vuln in vulnerabilities:
                self.security_output.append(f"Found: {vuln}")
                self.db.save_log('vulnerability_scan', f"Vulnerability found on {ip}: {vuln}", 'WARNING')
            self.status_bar.showMessage('Vulnerability scan complete')
        except Exception as e:
            self.security_output.append(f"Vulnerability scan error: {str(e)}")
            self.db.save_log('vulnerability_scan_error', str(e), 'ERROR')
            self.status_bar.showMessage('Vulnerability scan failed')

    def manage_firewall_rules(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Manage Firewall Rules')
        layout = QVBoxLayout()
        
        rules_table = QTableWidget()
        rules_table.setColumnCount(6)
        rules_table.setHorizontalHeaderLabels(['Name', 'Protocol', 'Port Range', 'Action', 'Source IP', 'Destination IP'])
        rules_table.setColumnWidth(0, 150)
        rules_table.setColumnWidth(1, 100)
        rules_table.setColumnWidth(2, 100)
        rules_table.setColumnWidth(3, 100)
        rules_table.setColumnWidth(4, 150)
        rules_table.setColumnWidth(5, 150)
        
        rules = self.db.get_firewall_rules()
        rules_table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            for col, value in enumerate(rule):
                rules_table.setItem(row, col, QTableWidgetItem(str(value)))
        
        layout.addWidget(rules_table)
        
        form_layout = QFormLayout()
        rule_name = QLineEdit()
        form_layout.addRow('Rule Name:', rule_name)
        
        protocol = QComboBox()
        protocol.addItems(['TCP', 'UDP', 'ICMP'])
        form_layout.addRow('Protocol:', protocol)
        
        port_range = QLineEdit('80')
        form_layout.addRow('Port Range:', port_range)
        
        action = QComboBox()
        action.addItems(['allow', 'block'])
        form_layout.addRow('Action:', action)
        
        source_ip = QLineEdit('0.0.0.0/0')
        form_layout.addRow('Source IP:', source_ip)
        
        destination_ip = QLineEdit('0.0.0.0/0')
        form_layout.addRow('Destination IP:', destination_ip)
        
        layout.addLayout(form_layout)
        
        buttons = QHBoxLayout()
        add_rule_button = QPushButton('Add Rule')
        add_rule_button.clicked.connect(lambda: self.add_firewall_rule(rule_name.text(), protocol.currentText(), port_range.text(), action.currentText(), source_ip.text(), destination_ip.text(), rules_table))
        buttons.addWidget(add_rule_button)
        
        remove_rule_button = QPushButton('Remove Selected Rule')
        remove_rule_button.clicked.connect(lambda: self.remove_firewall_rule(rules_table))
        buttons.addWidget(remove_rule_button)
        
        close_button = QPushButton('Close')
        close_button.clicked.connect(dialog.accept)
        buttons.addWidget(close_button)
        
        layout.addLayout(buttons)
        dialog.setLayout(layout)
        dialog.resize(800, 600)
        dialog.exec()
    
    def add_firewall_rule(self, rule_name, protocol, port_range, action, source_ip, destination_ip, rules_table):
        try:
            ipaddress.ip_network(source_ip)
            ipaddress.ip_network(destination_ip)
            self.firewall.add_rule(rule_name, protocol, port_range, action, source_ip, destination_ip)
            self.db.save_firewall_rule(rule_name, protocol, port_range, action, source_ip, destination_ip)
            rules = self.db.get_firewall_rules()
            rules_table.setRowCount(len(rules))
            for row, rule in enumerate(rules):
                for col, value in enumerate(rule):
                    rules_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.status_bar.showMessage('Firewall rule added')
            self.db.save_log('firewall_rule_add', f"Added rule: {rule_name}", 'INFO')
        except ValueError as e:
            self.status_bar.showMessage(f'Invalid IP address: {str(e)}')
            self.db.save_log('firewall_rule_error', str(e), 'ERROR')

    def remove_firewall_rule(self, rules_table):
        selected = rules_table.currentRow()
        if selected >= 0:
            rule_name = rules_table.item(selected, 0).text()
            if self.firewall.remove_rule(rule_name):
                rules_table.removeRow(selected)
                self.status_bar.showMessage('Firewall rule removed')
                self.db.save_log('firewall_rule_remove', f"Removed rule: {rule_name}", 'INFO')
            else:
                self.status_bar.showMessage('Failed to remove firewall rule')
                self.db.save_log('firewall_rule_remove_error', f"Failed to remove rule: {rule_name}", 'ERROR')

    def export_security_report(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Security Report', '', 'HTML Files (*.html);;PDF Files (*.pdf)')
        if filename:
            logs = self.db.conn.execute('SELECT timestamp, event_type, details, severity FROM network_logs WHERE event_type LIKE "%scan%"').fetchall()
            if filename.endswith('.html'):
                ReportGenerator.generate_html_report(logs, filename)
            elif filename.endswith('.pdf'):
                ReportGenerator.generate_pdf_report(logs, filename)
            self.status_bar.showMessage('Security report exported')
            self.db.save_log('security_report_export', f"Exported security report to {filename}", 'INFO')

    def update_security_graph(self):
        fig = self.security_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        scans = self.db.conn.execute('SELECT port, status FROM security_scans').fetchall()
        ports = [str(s[0]) for s in scans]
        statuses = [1 if s[1] == 'open' else 0 for s in scans]
        ax.bar(ports, statuses, color=['red' if s == 1 else 'green' for s in statuses])
        ax.set_title('Port Status')
        ax.set_xlabel('Port')
        ax.set_ylabel('Status (1=Open, 0=Closed)')
        fig.tight_layout()
        self.security_graph.draw()

    def analyze_logs(self):
        self.logs_output.clear()
        logs = self.db.conn.execute('SELECT timestamp, event_type, details, severity FROM network_logs').fetchall()
        severity_counts = {'INFO': 0, 'WARNING': 0, 'ERROR': 0}
        for log in logs:
            self.logs_output.append(f"[{log[0]}] {log[1]}: {log[2]} ({log[3]})")
            severity_counts[log[3]] += 1
        self.update_logs_graph(severity_counts)
        self.status_bar.showMessage('Log analysis complete')
        self.db.save_log('log_analysis', 'Analyzed logs', 'INFO')

    def update_logs_graph(self, severity_counts):
        fig = self.logs_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        labels = list(severity_counts.keys())
        counts = list(severity_counts.values())
        ax.pie(counts, labels=labels, autopct='%1.1f%%', colors=['#36A2EB', '#FFCE56', '#FF6384'])
        ax.set_title('Log Severity Distribution')
        fig.tight_layout()
        self.logs_graph.draw()

    def export_logs(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Logs', '', 'CSV Files (*.csv)')
        if filename:
            logs = self.db.conn.execute('SELECT timestamp, event_type, details, severity FROM network_logs').fetchall()
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Event Type', 'Details', 'Severity'])
                writer.writerows(logs)
            self.status_bar.showMessage('Logs exported')
            self.db.save_log('logs_export', f"Exported logs to {filename}", 'INFO')

    def clear_logs(self):
        self.db.clear_logs()
        self.logs_output.clear()
        self.status_bar.showMessage('Logs cleared')
        self.db.save_log('logs_clear', 'Cleared all logs', 'INFO')
        self.update_logs_graph({'INFO': 0, 'WARNING': 0, 'ERROR': 0})

    def start_performance_monitor(self):
        if not self.performance_monitor.isRunning():
            self.performance_monitor.start()
            self.status_bar.showMessage('Performance monitor started')
            self.db.save_log('performance_monitor', 'Started performance monitor', 'INFO')

    def stop_performance_monitor(self):
        self.performance_monitor.running = False
        self.status_bar.showMessage('Performance monitor stopped')
        self.db.save_log('performance_monitor_stop', 'Stopped performance monitor', 'INFO')

    def update_performance(self, metrics):
        self.performance_data['cpu'].append(metrics['cpu'])
        self.performance_data['memory'].append(metrics['memory'])
        self.performance_data['network'].append(metrics['network'])
        self.performance_data['packet_loss'].append(metrics['packet_loss'])
        self.performance_data['disk_usage'].append(metrics['disk_usage'])
        self.performance_data['active_connections'].append(metrics['active_connections'])
        self.performance_timestamps.append(datetime.datetime.now())
        
        # Keep only last 100 data points
        for key in self.performance_data:
            self.performance_data[key] = self.performance_data[key][-100:]
        self.performance_timestamps = self.performance_timestamps[-100:]
        
        self.performance_output.clear()
        self.performance_output.append(f"CPU Usage: {metrics['cpu']:.1f}%")
        self.performance_output.append(f"Memory Usage: {metrics['memory']:.1f}%")
        self.performance_output.append(f"Network Usage: {metrics['network']:,} bytes")
        self.performance_output.append(f"Packet Loss: {metrics['packet_loss']:.2f}%")
        self.performance_output.append(f"Disk Usage: {metrics['disk_usage']:.1f}%")
        self.performance_output.append(f"Active Connections: {metrics['active_connections']}")
        
        self.db.save_performance_metrics(
            metrics['cpu'],
            metrics['memory'],
            metrics['network'],
            metrics['packet_loss']
        )
        self.update_performance_graph()
        self.status_bar.showMessage('Performance metrics updated')

    def update_performance_graph(self):
        fig = self.performance_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        timestamps = [t.strftime('%H:%M:%S') for t in self.performance_timestamps]
        ax.plot(timestamps[-20:], self.performance_data['cpu'][-20:], label='CPU %', color='#36A2EB')
        ax.plot(timestamps[-20:], self.performance_data['memory'][-20:], label='Memory %', color='#FFCE56')
        ax.plot(timestamps[-20:], [x/1_000_000 for x in self.performance_data['network'][-20:]], label='Network (MB)', color='#FF6384')
        ax.set_title('Performance Metrics')
        ax.set_xlabel('Time')
        ax.set_ylabel('Usage')
        ax.legend()
        ax.tick_params(axis='x', rotation=45)
        fig.tight_layout()
        self.performance_graph.draw()

    def export_performance_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Performance Data', '', 'CSV Files (*.csv)')
        if filename:
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'CPU', 'Memory', 'Network', 'Packet Loss', 'Disk Usage', 'Active Connections'])
                for ts, cpu, mem, net, pl, disk, conn in zip(
                    self.performance_timestamps,
                    self.performance_data['cpu'],
                    self.performance_data['memory'],
                    self.performance_data['network'],
                    self.performance_data['packet_loss'],
                    self.performance_data['disk_usage'],
                    self.performance_data['active_connections']
                ):
                    writer.writerow([ts.isoformat(), cpu, mem, net, pl, disk, conn])
            self.status_bar.showMessage('Performance data exported')
            self.db.save_log('performance_export', f"Exported performance data to {filename}", 'INFO')

    def update_statistics(self):
        stats = self.stats.get_stats()
        self.stats_output.clear()
        self.stats_output.append('Packet Counts:')
        for proto, count in stats['packet_counts'].items():
            self.stats_output.append(f"  {proto}: {count}")
        self.stats_output.append('\nTraffic Volume:')
        self.stats_output.append(f"  Sent: {stats['traffic_volume']['sent']:,} bytes")
        self.stats_output.append(f"  Received: {stats['traffic_volume']['received']:,} bytes")
        self.stats_output.append(f"\nAverage Connection Time: {stats['avg_connection_time']:.2f} ms")
        self.update_stats_graph(stats)
        self.status_bar.showMessage('Statistics updated')
        self.db.save_log('stats_update', 'Updated network statistics', 'INFO')

    def update_stats_graph(self, stats):
        fig = self.stats_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        labels = list(stats['protocol_distribution'].keys())
        counts = list(stats['protocol_distribution'].values())
        ax.bar(labels, counts, color='#36A2EB')
        ax.set_title('Protocol Distribution')
        ax.set_xlabel('Protocol')
        ax.set_ylabel('Packet Count')
        fig.tight_layout()
        self.stats_graph.draw()

    def export_statistics(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Statistics', '', 'JSON Files (*.json)')
        if filename:
            stats = self.stats.get_stats()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2)
            self.status_bar.showMessage('Statistics exported')
            self.db.save_log('stats_export', f"Exported statistics to {filename}", 'INFO')

    def analyze_traffic(self):
        self.traffic_output.clear()
        stats = self.stats.get_stats()
        self.traffic_output.append('Traffic Analysis:')
        self.traffic_output.append(f"Total Sent: {stats['traffic_volume']['sent']:,} bytes")
        self.traffic_output.append(f"Total Received: {stats['traffic_volume']['received']:,} bytes")
        self.traffic_output.append('Protocol Distribution:')
        for proto, count in stats['protocol_distribution'].items():
            self.traffic_output.append(f"  {proto}: {count} packets")
        self.update_traffic_graph(stats)
        self.status_bar.showMessage('Traffic analysis complete')
        self.db.save_log('traffic_analysis', 'Completed traffic analysis', 'INFO')

    def update_traffic_graph(self, stats):
        fig = self.traffic_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        timestamps = [x['timestamp'] for x in stats['bandwidth_usage']]
        sent = [x['sent']/1_000_000 for x in stats['bandwidth_usage']]
        received = [x['received']/1_000_000 for x in stats['bandwidth_usage']]
        ax.plot(timestamps[-20:], sent[-20:], label='Sent (MB)', color='#36A2EB')
        ax.plot(timestamps[-20:], received[-20:], label='Received (MB)', color='#FF6384')
        ax.set_title('Bandwidth Usage')
        ax.set_xlabel('Time')
        ax.set_ylabel('Megabytes')
        ax.legend()
        ax.tick_params(axis='x', rotation=45)
        fig.tight_layout()
        self.traffic_graph.draw()

    def export_traffic_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Traffic Data', '', 'CSV Files (*.csv)')
        if filename:
            stats = self.stats.get_stats()
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Sent (Bytes)', 'Received (Bytes)'])
                for data in stats['bandwidth_usage']:
                    writer.writerow([data['timestamp'], data['sent'], data['received']])
            self.status_bar.showMessage('Traffic data exported')
            self.db.save_log('traffic_export', f"Exported traffic data to {filename}", 'INFO')

    def start_snmp_monitor(self):
        ip = self.snmp_ip.text()
        community = self.snmp_community.text()
        if self.snmp_monitor.connect(ip, community):
            self.snmp_output.append(f"Connected to SNMP device at {ip}")
            oids = ['1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.2.2.1.10.1', '1.3.6.1.2.1.2.2.1.16.1']  # Example OIDs
            for oid in oids:
                value = self.snmp_monitor.get_metric(oid)
                if value:
                    self.snmp_output.append(f"OID {oid}: {value}")
                    self.db.save_snmp_metric(ip, oid, value)
            self.update_snmp_graph(ip)
            self.status_bar.showMessage('SNMP monitor started')
            self.db.save_log('snmp_monitor', f"Started SNMP monitor for {ip}", 'INFO')
        else:
            self.snmp_output.append(f"Failed to connect to SNMP device at {ip}")
            self.status_bar.showMessage('SNMP connection failed')
            self.db.save_log('snmp_monitor_error', f"Failed to connect to SNMP device at {ip}", 'ERROR')

    def update_snmp_graph(self, device_ip):
        fig = self.snmp_graph.figure
        fig.clear()
        ax = fig.add_subplot(111)
        metrics = self.db.get_snmp_metrics(device_ip)
        timestamps = [m[0] for m in metrics]
        values = [float(m[2]) if m[2].replace('.', '', 1).isdigit() else 0 for m in metrics]
        ax.plot(timestamps[-20:], values[-20:], label='SNMP Metric', color='#36A2EB')
        ax.set_title(f'SNMP Metrics for {device_ip}')
        ax.set_xlabel('Time')
        ax.set_ylabel('Value')
        ax.tick_params(axis='x', rotation=45)
        ax.legend()
        fig.tight_layout()
        self.snmp_graph.draw()

    def schedule_scan(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Schedule Network Scan')
        layout = QFormLayout()
        
        interval_input = QSpinBox()
        interval_input.setRange(1, 1440)  # 1 minute to 1 day
        interval_input.setValue(60)  # Default 1 hour
        layout.addRow('Interval (minutes):', interval_input)
        
        ip_range_input = QLineEdit(self.ip_range_input.text())
        layout.addRow('IP Range:', ip_range_input)
        
        buttons = QHBoxLayout()
        save_button = QPushButton('Schedule')
        save_button.clicked.connect(lambda: self.apply_schedule(interval_input.value(), ip_range_input.text(), dialog))
        buttons.addWidget(save_button)
        
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        
        layout.addRow(buttons)
        dialog.setLayout(layout)
        dialog.exec()

    def apply_schedule(self, interval, ip_range, dialog):
        try:
            netaddr.IPNetwork(ip_range)
            self.scheduler.every(interval).minutes.do(self.run_scheduled_scan, ip_range=ip_range)
            self.status_bar.showMessage(f'Scan scheduled every {interval} minutes')
            self.db.save_log('schedule_scan', f"Scheduled scan every {interval} minutes for {ip_range}", 'INFO')
            dialog.accept()
        except ValueError as e:
            self.status_bar.showMessage(f'Invalid IP range: {str(e)}')
            self.db.save_log('schedule_scan_error', str(e), 'ERROR')

    def run_scheduled_scan(self, ip_range):
        self.scanner.ip_range = ip_range
        self.scanner.start()
        self.status_bar.showMessage(f'Scheduled scan started for {ip_range}')
        self.db.save_log('scheduled_scan', f"Started scheduled scan for {ip_range}", 'INFO')

    def export_all_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export All Data', '', 'JSON Files (*.json)')
        if filename:
            data = {
                'logs': self.db.conn.execute('SELECT * FROM network_logs').fetchall(),
                'configs': self.db.load_configs(),
                'knowledge': self.db.get_knowledge(self.language),
                'devices': self.db.get_devices(),
                'performance': self.db.conn.execute('SELECT * FROM performance_metrics').fetchall(),
                'security': self.db.conn.execute('SELECT * FROM security_scans').fetchall(),
                'firewall': self.db.get_firewall_rules(),
                'snmp': self.db.get_snmp_metrics()
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            self.status_bar.showMessage('All data exported')
            self.db.save_log('export_all', f"Exported all data to {filename}", 'INFO')

    def import_all_data(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Import All Data', '', 'JSON Files (*.json)')
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for config in data.get('configs', []):
                    self.db.save_config(config[1], config[2])
                for title, content in data.get('knowledge', []):
                    self.db.add_knowledge(title, content, self.language)
                for device in data.get('devices', []):
                    self.db.save_device(device[0], device[1], device[2], device[4])
                for metric in data.get('performance', []):
                    self.db.save_performance_metrics(metric[2], metric[3], metric[4], metric[5])
                for scan in data.get('security', []):
                    self.db.save_security_scan(scan[2], scan[3], scan[4])
                for rule in data.get('firewall', []):
                    self.db.save_firewall_rule(rule[0], rule[1], rule[2], rule[3], rule[4], rule[5])
                for metric in data.get('snmp', []):
                    self.db.save_snmp_metric(metric[2], metric[3], metric[4])
                self.update_network_map()
                self.update_config_table()
                self.update_knowledge_base()
                self.status_bar.showMessage('All data imported')
                self.db.save_log('import_all', f"Imported all data from {filename}", 'INFO')
            except Exception as e:
                self.status_bar.showMessage(f'Import failed: {str(e)}')
                self.db.save_log('import_all_error', str(e), 'ERROR')

    def backup_data(self):
        filename = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            with open(filename, 'wb') as f:
                for line in self.db.conn.iterdump():
                    f.write(f'{line}\n'.encode('utf-8'))
            self.status_bar.showMessage(f'Backup created: {filename}')
            self.db.save_log('backup', f"Created backup: {filename}", 'INFO')
        except Exception as e:
            self.status_bar.showMessage(f'Backup failed: {str(e)}')
            self.db.save_log('backup_error', str(e), 'ERROR')

    def restore_data(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Restore Backup', '', 'Database Files (*.db)')
        if filename:
            try:
                self.db.conn.close()
                os.remove(self.db.db_path)
                self.db.conn = sqlite3.connect(self.db.db_path)
                with open(filename, 'r', encoding='utf-8') as f:
                    sql_script = f.read()
                    self.db.conn.executescript(sql_script)
                self.db.conn.commit()
                self.update_network_map()
                self.update_config_table()
                self.update_knowledge_base()
                self.status_bar.showMessage('Backup restored')
                self.db.save_log('restore', f"Restored backup from {filename}", 'INFO')
            except Exception as e:
                self.status_bar.showMessage(f'Restore failed: {str(e)}')
                self.db.save_log('restore_error', str(e), 'ERROR')
                self.db.conn = sqlite3.connect(self.db.db_path)
                self.db.create_tables()

    def show_advanced_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Advanced Settings')
        layout = QFormLayout()
        
        log_level = QComboBox()
        log_level.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        log_level.setCurrentText(self.settings.value('log_level', 'INFO'))
        layout.addRow('Log Level:', log_level)
        
        scan_timeout = QSpinBox()
        scan_timeout.setRange(1, 60)
        scan_timeout.setValue(int(self.settings.value('scan_timeout', 10)))
        layout.addRow('Scan Timeout (seconds):', scan_timeout)
        
        max_threads = QSpinBox()
        max_threads.setRange(1, 100)
        max_threads.setValue(int(self.settings.value('max_threads', 10)))
        layout.addRow('Max Threads:', max_threads)
        
        buttons = QHBoxLayout()
        save_button = QPushButton('Save')
        save_button.clicked.connect(lambda: self.save_advanced_settings(log_level.currentText(), scan_timeout.value(), max_threads.value(), dialog))
        buttons.addWidget(save_button)
        
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        
        layout.addRow(buttons)
        dialog.setLayout(layout)
        dialog.exec()

    def save_advanced_settings(self, log_level, scan_timeout, max_threads, dialog):
        self.settings.setValue('log_level', log_level)
        self.settings.setValue('scan_timeout', scan_timeout)
        self.settings.setValue('max_threads', max_threads)
        logging.getLogger().setLevel(getattr(logging, log_level))
        dialog.accept()
        self.status_bar.showMessage('Advanced settings saved')
        self.db.save_log('advanced_settings', f"Updated advanced settings: log_level={log_level}, scan_timeout={scan_timeout}, max_threads={max_threads}", 'INFO')

    def show_help(self):
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle('Help')
        layout = QVBoxLayout()
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
            <h1>NetBridge Help</h1>
            <p>NetBridge is a comprehensive network management suite.</p>
            <h2>Features:</h2>
            <ul>
                <li><b>Network Diagnostics</b>: Scan and analyze network devices and connectivity.</li>
                <li><b>Network Optimizer</b>: Configure DNS, QoS, MTU, and other settings for optimal performance.</li>
                <li><b>Network Simulator</b>: Simulate network traffic and attacks for testing.</li>
                <li><b>Knowledge Base</b>: Access network-related guides and troubleshooting tips.</li>
                <li><b>Configuration Manager</b>: Save and load network configurations.</li>
                <li><b>Security Analyzer</b>: Scan for open ports and vulnerabilities.</li>
                <li><b>Log Analyzer</b>: Review and analyze network logs.</li>
                <li><b>Performance Monitor</b>: Track CPU, memory, and network usage.</li>
                <li><b>Network Statistics</b>: View packet counts and traffic volume.</li>
                <li><b>Traffic Analysis</b>: Analyze network traffic patterns.</li>
                <li><b>SNMP Monitor</b>: Monitor devices via SNMP.</li>
            </ul>
            <h2>Support:</h2>
            <p>Contact support hamidyaraliofficial@gmail.com for assistance.</p>
        """)
        layout.addWidget(help_text)
        close_button = QPushButton('Close')
        close_button.clicked.connect(help_dialog.accept)
        layout.addWidget(close_button)
        help_dialog.setLayout(layout)
        help_dialog.resize(600, 400)
        help_dialog.exec()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ThemeManager.apply_windows11_theme(app)
    window = NetBridge()
    window.show()
    sys.exit(app.exec())