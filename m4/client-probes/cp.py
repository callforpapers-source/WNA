import sys
from scapy.all import *

clientprobes=set()

def packet_handler(packet):
	if packet.haslayer(Dot11ProbeReq):
		pinfo = packet.info
		if len(pinfo)*b'\x00' != pinfo and len(packet.info) > 0:
			request = f"{packet.addr2} --**-- {pinfo}"
			if request not in clientprobes:
				clientprobes.add(request)
				print("Found a new probe request: " + request)

sniff(iface=sys.argv[1], prn=packet_handler)