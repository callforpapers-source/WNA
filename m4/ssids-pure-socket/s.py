import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
s.bind(('wlan0', 0x0003))
ap_list = set()
def parse_mac(mac):
	byte_str = map('{:02x}'.format, mac)
	return ':'.join(byte_str).upper()
while True:
	frame = s.recvfrom(65535)
	data = frame[0]
	if data[26]==128:
		s_len = data[63]
		ssid = data[64:64+s_len]
		if ssid not in ap_list:
			print(parse_mac(data[42:47]), ssid, data[76+s_len])
			ap_list.add(ssid)
