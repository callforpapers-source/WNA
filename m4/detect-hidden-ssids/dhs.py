from scapy.all import *
import sys

hidden_ssids = set()

def packet_handler(packet):
	if packet.haslayer(Dot11Beacon):
		pinfo = packet.info
		if len(pinfo)*b'\x00' == pinfo:
			if packet.addr3 not in hidden_ssids:
				hidden_ssids.add(packet.addr3)
				print(f"Found a hidden ssid with the following bssid: {packet.addr3}")
	elif packet.haslayer(Dot11ProbeResp) and (packet.addr3 in hidden_ssids):
		print(f"The hidden access point along with the ssid: {packet.info} - {packet.addr3}")


sniff(iface=sys.argv[1], prn=packet_handler)