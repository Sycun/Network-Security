import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import importlib
import threading
from datetime import datetime

class ToolBox:
    def __init__(self, master):
        self.master = master
        master.title("网络安全工具箱 v1.0")
        master.geometry("1200x800")

        # 工具配置字典（工具文件名: {显示名称, 参数配置}）
        self.tools = {
            'ssh_bruteforce.py': {
                'name': 'SSH暴力破解',
                'params': [
                    {'label': '目标IP', 'type': 'entry'},
                    {'label': '用户名', 'type': 'entry'},
                    {'label': '密码字典', 'type': 'file'},
                    {'label': '端口号', 'type': 'entry', 'default': '22'},
                    {'label': '线程数', 'type': 'entry', 'default': '5'}
                ]
            },
            'port_scanner.py': {
                'name': '端口扫描',
                'params': [
                    {'label': '目标IP', 'type': 'entry'},
                    {'label': '端口范围', 'type': 'entry', 'default': '1-1024'},
                    {'label': '扫描类型', 'type': 'combobox', 'options': ['TCP', 'UDP']},
                    {'label': '超时时间(s)', 'type': 'entry', 'default': '1'}
                ]
            },
            'web_directory_bruteforce.py': {
                'name': 'Web目录爆破',
                'params': [
                    {'label': '目标URL', 'type': 'entry'},
                    {'label': '字典文件', 'type': 'file'},
                    {'label': '扩展名', 'type': 'entry', 'default': 'php,html'},
                    {'label': '线程数', 'type': 'entry', 'default': '10'}
                ]
            }
        }

        # 创建界面布局
        self.create_widgets()
        self.load_tool_list()

    def create_widgets(self):
        # 左侧工具列表
        self.tool_frame = ttk.LabelFrame(self.master, text="可用工具", width=200)
        self.tool_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # 中间参数区域
        self.param_frame = ttk.LabelFrame(self.master, text="参数配置")
        self.param_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 右侧结果区域
        self.result_frame = ttk.LabelFrame(self.master, text="执行结果")
        self.result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 结果输出文本框
        self.result_text = scrolledtext.ScrolledText(self.result_frame, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 底部控制按钮
        self.control_frame = ttk.Frame(self.master)
        self.control_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.start_btn = ttk.Button(self.control_frame, text="开始执行", command=self.start_execution)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(self.control_frame, text="停止", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

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

    def execute_tool(self, tool_file, params):
        """执行目标工具并捕获输出"""
        try:
            module = importlib.import_module(tool_file[:-3])
            result = module.main(**params)  # 假设工具脚本有main函数
            
            self.master.after(0, self.log_output, "\n执行结果:")
            self.master.after(0, self.log_output, result)
            
        except Exception as e:
            self.master.after(0, self.log_output, f"错误发生: {str(e)}")
        finally:
            self.master.after(0, self.reset_buttons)

    def log_output(self, message):
        """在结果区域记录信息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.result_text.see(tk.END)

    def reset_buttons(self):
        """重置按钮状态"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    gui = ToolBox(root)
    root.mainloop()
