from scapy.all import *

def scan(pkt):
	if ARP in pkt and pkt[ARP].op == 2:
		return pkt.sprintf("[+] MAC: %ARP.hwsrc% IP: %ARP.psrc%")
		
sniff(prn=scan, filter="arp", store = 0)
