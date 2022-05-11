from scapy.all import * 
import sys

def scan(ip):
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc='12.168.1.106', pdst=ip)
	res = srp(packet, timeout = 1, verbose = 0)
	res[0].summary(lambda s,r: r.sprintf("[*] %Ether.src% %ARP.psrc%") )
				
if __name__ == "__main__":
	if len(sys.argv) == 2:
		try:
			if sys.argv[1][-1] == 'X' or sys.argv[1][-1] == 'x':
				ip = sys.argv[1]
				ip = ip[0:-1] + "0/24"
				scan(ip)
			else:
				print("[!] IP incorrecta. Formato: 192.168.1.X")
		except KeyboardInterrupt:
			print("\n[!] Saliendo... Ctrl+C")
	else:
		print(f"[!] Uso: sudo python {sys.argv[0]} <ip>\n\t Example: sudo python {sys.argv[0]} 192.168.1.X")
