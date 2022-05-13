from scapy.all import *
import argparse
import os
import sys

def scan_sniff(pkt):
	if ARP in pkt and pkt[ARP].op == 2:
		return pkt.sprintf("[+] MAC: %ARP.hwsrc% IP: %ARP.psrc%")

def send_arp(ip):
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc='12.168.1.106', pdst=ip)
	res = srp(packet, timeout = 2, verbose = 0)
	res[0].summary(lambda s,r: r.sprintf("[*] %Ether.src% %ARP.psrc%"))
	
def active(range_ip, mode):
	if mode == '1':
		for i in range(1,255):
			ip = range_ip[0:-4] + str(i)
			send_arp(ip)
	elif mode == '2':
		send_arp(range_ip)
		
if __name__ == "__main__":

	parser = argparse.ArgumentParser(description ='ARP Scan Tool by @aalmeidar',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=('''[*] Example:
		
	'''))

	parser.add_argument('-m', '--mode', default='0', help='Scan Mode (0=Passive, 1=Active Slow, 2=Active Fast)')
	parser.add_argument('-r', '--range', default='192.168.1.0/24', help='Range Host (Default: 192.168.1.0/24)')
	parser.add_argument('-o', '--output', action='store_true', help='Save Output')

	args = parser.parse_args()

	if args.output:
		name_file = f"output.txt"
		try:
			f = open(name_file, "x")
			f.close()
			sys.stdout(name_file, "w")
		except FileExistsError:
			sys.stdout = open(name_file, "a")
			print("\n")

	if args.mode == '0':
		sniff(prn=scan_sniff, filter="arp", store = 0)
	elif args.mode == '1' or args.mode == '2':
		if args.range[-4:] == "0/24":
			active(args.range, args.mode)
		else:
			print(f"[!] Error. Unknown Range {args.range}")
	else:
		print(f"[!] Error. Unknown Mode {args.mode}")
		sys.exit()	
