import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import importlib
import json
import re
import threading
from datetime import datetime

# 在文件开头添加ImageGrab导入
class ToolBox:
    def __init__(self, master):
        self.master = master
        master.title("网络安全工具箱 v1.1")
        
        # 加载工具配置
        self.load_tool_config()
        
        # 线程控制
        self.running = False
        self.stop_event = threading.Event()
        
        # 创建界面布局
        self.create_widgets()
        self.load_tool_list()

    def load_tool_config(self):
        """从JSON文件加载工具配置"""
        try:
            with open('tools_config.json', 'r', encoding='utf-8') as f:
                self.tools = json.load(f)['tools']
        except Exception as e:
            messagebox.showerror("配置错误", f"无法加载工具配置: {str(e)}")
            sys.exit(1)

    def create_widgets(self):
        # 左侧工具列表
        self.tool_frame = ttk.LabelFrame(self.master, text="可用工具", width=200)
        # 在__init__方法中添加样式配置
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', font=('微软雅黑', 10))
        self.style.configure('TButton', padding=6, foreground='#2c3e50')
        self.style.map('TButton', foreground=[('active', '#2980b9')])

        # 主布局使用grid
        self.master.grid_columnconfigure(0, weight=2)
        self.master.grid_columnconfigure(1, weight=4)
        self.master.grid_columnconfigure(2, weight=4)
        self.master.grid_rowconfigure(0, weight=1)

        # 功能区
        self.tool_frame = ttk.LabelFrame(self.master, text="可用工具")
        self.tool_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # 参数区
        self.param_frame = ttk.LabelFrame(self.master, text="参数配置")
        self.param_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.param_frame.grid_columnconfigure(0, weight=1)
        self.param_frame.grid_rowconfigure(1, weight=1)
        
        # 参数区按钮容器使用grid布局
        btn_container = ttk.Frame(self.param_frame)
        btn_container.grid(row=0, column=0, sticky="e", pady=5)
        self.param_frame.grid_columnconfigure(0, weight=1)
        
        # 输入参数容器
        self.input_container = ttk.Frame(self.param_frame)
        self.input_container.grid(row=1, column=0, sticky="nsew")
        self.param_frame.grid_rowconfigure(1, weight=1)

        # 响应式布局处理
        self.master.bind("<Configure>", self.on_window_resize)
        
        # 设置最小窗口尺寸
        self.master.minsize(800, 500)
        
        # 参数区按钮容器
        btn_container = ttk.Frame(self.param_frame)
        btn_container.grid(row=0, column=0, sticky="e", pady=5)
        self.param_frame.grid_columnconfigure(0, weight=1)
        
        self.start_btn = ttk.Button(btn_container, text="开始执行", width=8, command=self.start_execution, style='Start.TButton')
        self.start_btn.grid(row=0, column=0, padx=3)
        
        self.stop_btn = ttk.Button(btn_container, text="停止", width=8, state=tk.DISABLED, command=self.stop_execution, style='Stop.TButton')
        self.stop_btn.grid(row=0, column=1, padx=3)
        btn_container.grid_columnconfigure(0, weight=1)

        # 结果区
        self.result_frame = ttk.LabelFrame(self.master, text="执行结果")
        self.result_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        # 配置按钮样式
        self.style.configure('Start.TButton', background='#4CAF50', foreground='white')
        self.style.configure('Stop.TButton', background='#F44336', foreground='white')
        self.style.map('Start.TButton',
            background=[('active', '#45a049'), ('disabled', '#cccccc')],
            foreground=[('disabled', '#666666')])
        self.style.map('Stop.TButton',
            background=[('active', '#d32f2f'), ('disabled', '#cccccc')],
            foreground=[('disabled', '#666666')])
        self.result_text = scrolledtext.ScrolledText(self.result_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 创建界面布局
        self.tool_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.param_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.result_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        # 配置网格权重
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=2)
        self.master.grid_columnconfigure(2, weight=2)
        self.master.grid_rowconfigure(0, weight=1)

        # 底部控制按钮
        self.control_frame = ttk.Frame(self.master)
        self.control_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        self.master.grid_rowconfigure(1, weight=0)

        # 按钮容器使用水平布局
        # 底部控制按钮容器
        btn_container = ttk.Frame(self.control_frame)
        btn_container.grid(row=0, column=0, sticky="e")
        self.control_frame.grid_columnconfigure(0, weight=1)
        
        # 进度条与按钮水平排列
        self.progress = ttk.Progressbar(btn_container, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=(0,20), fill=tk.X, expand=True)
        
        # 按钮组Frame
        button_group = ttk.Frame(btn_container)
        button_group.pack(side=tk.RIGHT)
        
        self.start_btn = ttk.Button(button_group, text="开始执行", width=12, command=self.start_execution)
        self.start_btn.pack(side=tk.LEFT, padx=5, ipady=3)
        
        self.stop_btn = ttk.Button(button_group, text="停止", width=12, state=tk.DISABLED, command=self.stop_execution)
        self.stop_btn.pack(side=tk.LEFT, padx=5, ipady=3)
        
        # 设置最小尺寸
        self.control_frame.config(width=680, height=60)
        btn_container.config(width=650)
        button_group.config(width=260)

    def load_tool_list(self):
        """加载工具列表到左侧面板"""
        for tool_file in self.tools:
            btn = ttk.Button(
                self.tool_frame,
                text=self.tools[tool_file]['name'],
                command=lambda f=tool_file: self.show_parameters(f)
            )
            btn.pack(fill=tk.X, padx=2, pady=2)

    def show_parameters(self, tool_file):
        """显示选定工具的输入参数"""
        # 清空当前参数区域
        for widget in self.param_frame.winfo_children():
            widget.destroy()

        tool_config = self.tools[tool_file]
        ttk.Label(self.param_frame, text=tool_config['name'], font=('Arial', 12, 'bold')).pack(anchor=tk.W)

        self.input_widgets = {}
        row = 1
        for param in tool_config['params']:
            frame = ttk.Frame(self.param_frame)
            frame.pack(fill=tk.X, padx=5, pady=2)

            label = ttk.Label(frame, text=param['label'] + ":", width=12)
            label.pack(side=tk.LEFT)

            if param['type'] == 'entry':
                widget = ttk.Entry(frame)
                if 'default' in param:
                    widget.insert(0, param['default'])
            elif param['type'] == 'file':
                widget = ttk.Entry(frame, width=20)
                browse_btn = ttk.Button(frame, text="浏览...", 
                    command=lambda w=widget: self.select_file(w))
                browse_btn.pack(side=tk.RIGHT)
            elif param['type'] == 'combobox':
                widget = ttk.Combobox(frame, values=param['options'])
                widget.current(0)

            widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.input_widgets[param['label']] = widget

    def select_file(self, entry_widget):
        """文件选择对话框"""
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def start_execution(self):
        """启动工具执行"""
        if not self.validate_inputs():
            return
        
        self.running = True
        self.stop_event.clear()
        
        current_tool = [k for k,v in self.tools.items() if v['name'] in self.param_frame.winfo_children()[0].cget("text")][0]
        params = {k: v.get() for k,v in self.input_widgets.items()}
        
        # 在结果区域显示执行信息
        self.log_output(f"开始执行 {self.tools[current_tool]['name']}")
        self.log_output("参数配置:")
        for k,v in params.items():
            self.log_output(f"  {k}: {v}")
        self.log_output("-"*50)

        # 在新线程中执行工具
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        thread = threading.Thread(
            target=self.execute_tool,
            args=(current_tool, params)
        )
        thread.start()

    def stop_execution(self):
        """停止当前执行的任务"""
        self.stop_event.set()
        self.log_output("操作已中止", "WARNING")

    def execute_tool(self, tool_file, params):
        """执行目标工具并捕获输出"""
        try:
            if self.stop_event.is_set():
                return
            
            module = importlib.import_module(tool_file[:-3])
            
            # 添加执行超时控制
            result = module.main(**params) if not self.stop_event.is_set() else ""
            
            if not self.stop_event.is_set():
                self.master.after(0, self.log_output, "\n执行完成!", "SUCCESS")
            
        except Exception as e:
            self.master.after(0, self.log_output, f"错误发生: {str(e)}", "ERROR")
        finally:
            self.master.after(0, self.reset_buttons)

    def log_output(self, message, level="INFO"):
        """分级日志输出"""
        color_map = {
            'INFO': '#2c3e50',
            'WARNING': '#f39c12',
            'ERROR': '#e74c3c',
            'SUCCESS': '#27ae60'
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.result_text.insert(tk.END, f"[{timestamp}] ", ('timestamp',))
        self.result_text.insert(tk.END, f"{message}\n", (level,))
        self.result_text.tag_configure('timestamp', foreground='#7f8c8d')
        self.result_text.tag_configure(level, foreground=color_map.get(level, 'black'))
        self.result_text.see(tk.END)

    def reset_buttons(self):
        """重置按钮状态"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def validate_inputs(self):
        """验证输入参数有效性"""
        try:
            # 示例验证：IP地址格式
            # 仅验证包含目标IP的工具
            if '目标IP' in self.input_widgets:
                ip = self.input_widgets['目标IP'].get()
                if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                    raise ValueError("无效的IP地址格式")
            return True
        except Exception as e:
            self.log_output(f"输入验证失败: {str(e)}", level="ERROR")
            return False

    def change_theme(self, event):
        """切换界面主题"""
        self.style.theme_use(self.style_combobox.get())

    def log_output(self, message, level="INFO"):
        """分级日志输出"""
        color_map = {
            'INFO': '#2c3e50',
            'WARNING': '#f39c12',
            'ERROR': '#e74c3c',
            'SUCCESS': '#27ae60'
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.result_text.insert(tk.END, f"[{timestamp}] ", ('timestamp',))
        self.result_text.insert(tk.END, f"{message}\n", (level,))
        self.result_text.tag_configure('timestamp', foreground='#7f8c8d')
        self.result_text.tag_configure(level, foreground=color_map.get(level, 'black'))
        self.result_text.see(tk.END)

    def on_window_resize(self, event):
        """窗口尺寸变化时的响应式处理"""
        if event.widget == self.master:
            # 动态调整参数输入框宽度
            for child in self.input_container.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.config(width=int(self.param_frame.winfo_width()*0.8//10))

if __name__ == "__main__":
    root = tk.Tk()
    app = ToolBox(root)
    root.mainloop()
