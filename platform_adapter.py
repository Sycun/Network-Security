import platform
import os

class SystemAdapter:
    @staticmethod
    def get_interface_prefix():
        system = platform.system()
        if system == 'Darwin':
            return 'en'
        elif system == 'Linux':
            return 'eth'
        return 'eth'

    @staticmethod
    def get_sudo_command():
        if platform.system() == 'Darwin':
            return 'sudo'
        return 'sudo'

    @staticmethod
    def path_join(*args):
        return os.path.join(*args)

    @classmethod
    def get_default_interface(cls):
        prefix = cls.get_interface_prefix()
        interfaces = [f"{prefix}0", f"{prefix}1", "lo0"]
        for iface in interfaces:
            if os.path.exists(f"/sys/class/net/{iface}") or \
               (platform.system() == 'Darwin' and iface in os.listdir('/dev')):
                return iface
        return 'lo0'