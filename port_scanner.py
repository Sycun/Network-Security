import socket
import multiprocessing
from multiprocessing import Queue
import platform

def port_scan(target, port, result_queue):
    sock_type = socket.SOCK_STREAM
    if platform.system() == 'Linux':
        sock_type = socket.SOCK_STREAM | socket.SOCK_NONBLOCK
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"端口 {port} 开放")
        sock.close()
    except Exception as e:
        pass

def worker(queue):
    while True:
        port = queue.get()
        port_scan(target, port)
        queue.task_done()

if __name__ == "__main__":
    target = input("输入目标IP: ")
    start_port = int(input("起始端口: "))
    end_port = int(input("结束端口: "))
    
    queue = Queue()
    for _ in range(50):
        t = multiprocessing.Process(target=worker, args=(queue,))
        t.daemon = True
        t.start()
    
    for port in range(start_port, end_port+1):
        queue.put(port)
    
    queue.join()