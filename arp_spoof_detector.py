from scapy.all import sniff, ARP
import time

arp_table = {}

def arp_monitor(packet):
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        
        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"[!] ARP欺骗警报: IP {ip} MAC地址变更 ({arp_table[ip]} -> {mac})")
        else:
            arp_table[ip] = mac

if __name__ == "__main__":
    print("启动ARP欺骗检测器...")
    sniff(prn=arp_monitor, filter="arp", store=0)