import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")

        self.start_button = tk.Button(root, text="Start Capture", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.clear_button = tk.Button(root, text="Clear", command=self.clear_output)
        self.clear_button.pack(pady=10)

        self.output_text = scrolledtext.ScrolledText(root, width=100, height=30)
        self.output_text.pack(pady=10)

        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "Starting packet capture...\n")
        self.output_text.see(tk.END)
        self.sniffer_thread()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_text.insert(tk.END, "Stopping packet capture...\n")
        self.output_text.see(tk.END)

    def clear_output(self):
        self.output_text.delete('1.0', tk.END)

    def sniffer_thread(self):
        if self.sniffing:
            sniff(prn=self.packet_callback, store=0, timeout=1)
            self.root.after(1000, self.sniffer_thread)

    def packet_callback(self, packet):
        packet_info = ""

        if Ether in packet:
            eth_layer = packet[Ether]
            packet_info += f"Ethernet Frame:\n"
            packet_info += f"Source MAC: {eth_layer.src}\n"
            packet_info += f"Destination MAC: {eth_layer.dst}\n"

        if IP in packet:
            ip_layer = packet[IP]
            packet_info += f"IP Packet:\n"
            packet_info += f"Source IP: {ip_layer.src}\n"
            packet_info += f"Destination IP: {ip_layer.dst}\n"
            packet_info += f"Version: {ip_layer.version}\n"
            packet_info += f"Header Length: {ip_layer.ihl}\n"
            packet_info += f"Type of Service: {ip_layer.tos}\n"
            packet_info += f"Total Length: {ip_layer.len}\n"
            packet_info += f"Identification: {ip_layer.id}\n"
            packet_info += f"Flags: {ip_layer.flags}\n"
            packet_info += f"Fragment Offset: {ip_layer.frag}\n"
            packet_info += f"Time to Live: {ip_layer.ttl}\n"
            packet_info += f"Protocol: {ip_layer.proto}\n"
            packet_info += f"Header Checksum: {ip_layer.chksum}\n"
            packet_info += f"Options: {ip_layer.options}\n"

            if ip_layer.proto == 1 and ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_info += f"ICMP Packet:\n"
                packet_info += f"Type: {icmp_layer.type}\n"
                packet_info += f"Code: {icmp_layer.code}\n"
                packet_info += f"Checksum: {icmp_layer.chksum}\n"
                packet_info += f"ID: {icmp_layer.id}\n"
                packet_info += f"Sequence: {icmp_layer.seq}\n"

            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info += f"TCP Segment:\n"
                packet_info += f"Source Port: {tcp_layer.sport}\n"
                packet_info += f"Destination Port: {tcp_layer.dport}\n"
                packet_info += f"Sequence Number: {tcp_layer.seq}\n"
                packet_info += f"Acknowledgment Number: {tcp_layer.ack}\n"
                packet_info += f"Data Offset: {tcp_layer.dataofs}\n"
                packet_info += f"Reserved: {tcp_layer.reserved}\n"
                packet_info += f"Flags: {tcp_layer.flags}\n"
                packet_info += f"Window Size: {tcp_layer.window}\n"
                packet_info += f"Checksum: {tcp_layer.chksum}\n"
                packet_info += f"Urgent Pointer: {tcp_layer.urgptr}\n"
                packet_info += f"Options: {tcp_layer.options}\n"

            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info += f"UDP Datagram:\n"
                packet_info += f"Source Port: {udp_layer.sport}\n"
                packet_info += f"Destination Port: {udp_layer.dport}\n"
                packet_info += f"Length: {udp_layer.len}\n"
                packet_info += f"Checksum: {udp_layer.chksum}\n"

            packet_info += f"Payload: {bytes(packet[IP].payload)}\n"

        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_info += f"ARP Packet:\n"
            packet_info += f"Hardware Type: {arp_layer.hwtype}\n"
            packet_info += f"Protocol Type: {arp_layer.ptype}\n"
            packet_info += f"Hardware Size: {arp_layer.hwlen}\n"
            packet_info += f"Protocol Size: {arp_layer.plen}\n"
            packet_info += f"Operation: {arp_layer.op}\n"
            packet_info += f"Source MAC: {arp_layer.hwsrc}\n"
            packet_info += f"Source IP: {arp_layer.psrc}\n"
            packet_info += f"Destination MAC: {arp_layer.hwdst}\n"
            packet_info += f"Destination IP: {arp_layer.pdst}\n"

        packet_info += "-" * 50 + "\n"
        self.output_text.insert(tk.END, packet_info)
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
