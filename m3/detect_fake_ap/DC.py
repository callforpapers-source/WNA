from scapy.all import *
import os
import time


obtained_ap = {}
iface = "wlan0"
conf.verb = 0
non_bssids = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
fopen = open('mac_prefix').read().split('\n')

def detect_fake_ap(obtained_ap):
	same_essids = {}
	for i in obtained_ap:
		essid = obtained_ap[i]['essid']
		if essid not in same_essids:
			same_essids[essid] = (i, obtained_ap[i]['sec'])
		else:
			if obtained_ap[i]['sec'] != same_essids[essid][1]:
				print('Fake Access Point(same ssid but different encryption):', i, '\t', essid, '\t', obtained_ap[i]['sec'])
			elif i != same_essids[essid][0]:
				print('Fake Access Point(same ssid but different mac address):', i, '\t', essid, '\t', obtained_ap[i]['sec'])

def channel_hop():
	for i in range(14):
		os.system(f"iwconfig {iface} channel {i}")
		sniff(iface=iface, count=15, prn=obtain_ap_and_clients_handler)

def detect_mac_device(mac):
	for i in fopen:
		row = i.split('|')
		pref, device = row[0], row[1]
		mac_pref = ''.join(mac.split(':')[:3]).upper()
		if pref == mac_pref:
			return device
	return "unknown"

def show_tree(obtained_ap):
	time.sleep(.5)
	os.system('clear')
	print(f"BSSID{' '*12} CH   SEC     ESSID")
	for i in obtained_ap:
		print(f"{obtained_ap[i]['bssid']}  {obtained_ap[i]['channel']}\t{obtained_ap[i]['sec']}\t{obtained_ap[i]['essid']}")

def add_ap(packet):
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

	obtained_ap[bssid] = {'essid': essid, 'bssid': bssid, 'channel': chan, 'clients': {}, 'sec': '/'.join(secs)}

def obtain_ap_and_clients_handler(packet):
	if not packet.haslayer(Dot11):
		return
	bssid = packet[Dot11].addr3
	if not packet.addr1 or not packet.addr2:
		return
	if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
		if bssid not in obtained_ap:
			add_ap(packet)
	# filter packets based on their mac address
	if packet.addr1 in non_bssids or packet.addr2 in non_bssids:
		return
	show_tree(obtained_ap)
	detect_fake_ap(obtained_ap)

if __name__ == '__main__':
	os.system('clear')
	while True:
		channel_hop()
	# sniff(iface=iface, prn=obtain_ap_and_clients_handler)
