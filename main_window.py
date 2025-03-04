from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel
from PyQt5.QtCore import QThread, pyqtSignal
import sys

class ARPSpoofThread(QThread):
    output = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    def run(self):
        from arp_spoof_detector import ARPSpoofDetector
        detector = ARPSpoofDetector(self.interface, self.output)
        detector.start()

class SSLAnalyzerThread(QThread):
    output = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        from ssl_tls_analyzer import analyze_ssl
        analyze_ssl(self.target, self.output)

class PortScannerThread(QThread):
    output = pyqtSignal(str)

    def __init__(self, target, start_port, end_port):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port

    def run(self):
        from port_scanner import port_scan, queue
        import threading
        
        queue = Queue()
        for _ in range(50):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
        
        for port in range(self.start_port, self.end_port+1):
            queue.put(port)
        
        queue.join()
        self.output.emit('扫描完成')

class DNSMonitorThread(QThread):
    output = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        from dns_monitor import DNSMonitor
        self.monitor = DNSMonitor(self.output)

    def run(self):
        self.monitor.start_monitoring()

    def terminate(self):
        self.monitor.stop_monitoring()
        super().terminate()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.check_privileges()
        self.init_ui()
        self.threads = []

    def check_privileges(self):
        from PyQt5.QtWidgets import QMessageBox
        import os
        
        if os.name != 'nt' and os.geteuid() != 0:
            QMessageBox.warning(self, '权限警告',
                '部分功能需要管理员权限运行！\n请使用sudo重新启动程序以获得完整功能。',
                QMessageBox.Ok)
    def init_ui(self):
        self.setWindowTitle('网络安全工具集')
        self.setGeometry(300, 300, 800, 600)

        # 创建标签页
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # 添加DNS监控标签页
        self.dns_tab = DNSTab()
        self.tabs.addTab(self.dns_tab, 'DNS监控')

        # 添加端口扫描标签页
        self.port_scan_tab = PortScannerTab()
        self.tabs.addTab(self.port_scan_tab, '端口扫描')

        # 添加ARP欺骗检测标签页
        self.arp_tab = ARPSpoofTab()
        self.tabs.addTab(self.arp_tab, 'ARP检测')

        # 添加SSL/TLS分析标签页
        self.ssl_tab = SSLAnalyzerTab()
        self.tabs.addTab(self.ssl_tab, 'SSL分析')

class DNSTab(QWidget):
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.init_ui()
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)

    def start_monitoring(self):
        self.monitor_thread = DNSMonitorThread()
        self.monitor_thread.output.connect(self.output_area.append)
        self.monitor_thread.start()
        self.output_area.append('DNS监控已启动...')

    def stop_monitoring(self):
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.terminate()
            self.output_area.append('DNS监控已停止')

    def init_ui(self):
        layout = QVBoxLayout()
        
        # 控制按钮
        self.start_btn = QPushButton('开始监控', self)
        self.stop_btn = QPushButton('停止监控', self)
        
        # 输出显示
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.output_area)
        self.setLayout(layout)

class PortScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.init_ui()
        self.scan_btn.clicked.connect(self.start_scan)

class ARPSpoofTab(QWidget):
    def __init__(self):
        super().__init__()
        self.detector_thread = None
        self.init_ui()
        self.start_btn.clicked.connect(self.start_detection)
        self.stop_btn.clicked.connect(self.stop_detection)

    def start_detection(self):
        from PyQt5.QtWidgets import QMessageBox
        import os
        
        if os.geteuid() != 0:
            QMessageBox.critical(self, '权限不足',
                'ARP欺骗检测需要管理员权限！\n请使用sudo重新启动程序。',
                QMessageBox.Ok)
            return
        
        interface = self.interface_input.text()
        self.detector_thread = ARPSpoofThread(interface)
        self.detector_thread.output.connect(self.output_area.append)
        self.detector_thread.start()
        self.output_area.append(f'开始检测 {interface} 接口ARP欺骗...')
    def stop_detection(self):
        if self.detector_thread and self.detector_thread.isRunning():
            self.detector_thread.quit()
            self.output_area.append('ARP检测已停止')

    def init_ui(self):
        layout = QVBoxLayout()
        
        self.interface_input = QLineEdit()
        self.interface_input.setText(SystemAdapter.get_default_interface())
        self.start_btn = QPushButton('开始检测')
        self.stop_btn = QPushButton('停止检测')
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        layout.addWidget(QLabel('网络接口:'))
        layout.addWidget(self.interface_input)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.output_area)
        self.setLayout(layout)

class SSLAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.analyzer_thread = None
        self.init_ui()
        self.analyze_btn.clicked.connect(self.start_analysis)

    def start_analysis(self):
        target = self.target_input.text()
        self.analyzer_thread = SSLAnalyzerThread(target)
        self.analyzer_thread.output.connect(self.output_area.append)
        self.analyzer_thread.start()
        self.output_area.append(f'开始分析 {target} 的SSL/TLS配置...')

    def init_ui(self):
        layout = QVBoxLayout()
        
        self.target_input = QLineEdit()
        self.analyze_btn = QPushButton('开始分析')
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        layout.addWidget(QLabel('目标地址:'))
        layout.addWidget(self.target_input)
        layout.addWidget(self.analyze_btn)
        layout.addWidget(self.output_area)
        self.setLayout(layout)

    def start_scan(self):
        target = self.ip_input.text()
        try:
            start_port = int(self.start_port.text())
            end_port = int(self.end_port.text())
            
            self.scan_thread = PortScannerThread(target, start_port, end_port)
            self.scan_thread.output.connect(self.output_area.append)
            self.scan_thread.start()
            self.output_area.append(f'开始扫描 {target}:{start_port}-{end_port}')
        except ValueError:
            self.output_area.append('错误：端口号必须为数字')
        except Exception as e:
            self.output_area.append(f'扫描错误: {str(e)}')

    def init_ui(self):
        layout = QVBoxLayout()
        
        # 输入字段
        self.ip_input = QLineEdit()
        self.start_port = QLineEdit()
        self.end_port = QLineEdit()
        
        # 控制按钮
        self.scan_btn = QPushButton('开始扫描')
        
        # 输出显示
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        layout.addWidget(QLabel('目标IP:'))
        layout.addWidget(self.ip_input)
        layout.addWidget(QLabel('起始端口:'))
        layout.addWidget(self.start_port)
        layout.addWidget(QLabel('结束端口:'))
        layout.addWidget(self.end_port)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.output_area)
        self.setLayout(layout)

if __name__ == '__main__':
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())