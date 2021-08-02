import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
s.bind(('wlan0', 0x0003))
clients = {}
def parse_mac(mac):
	byte_str = map('{:02x}'.format, mac)
	return ':'.join(byte_str).upper()

while True:
	packet = s.recvfrom(2048)
	data = packet[0]
	if data[26] == 176:
		sender = parse_mac(data[30:35])
		receiver = parse_mac(data[36:41])
		if sender not in clients and receiver not in clients:
			clients[receiver] = [0, sender]
			print(receiver, 'wanna login to the following access point:', sender)
		elif receiver not in clients and sender in clients:
			if clients[sender][0]:
				print(receiver, 'accepted the', sender, 'request')
	elif data[26] == 212:
		sender = parse_mac(data[30:35])
		if sender in clients:
			clients[sender][0] = 1
			print('ACK:', 'receiver?', sender)
	elif data[26] == 160:
		sender = parse_mac(data[30:35])
		if sender in clients:
			print(sender, "couldn't connect to the", clients[sender][1])
			del clients[sender]
	elif data[26] == 208:
		sender = parse_mac(data[30:35])
		if sender in clients:
			print(sender, "could connect to the", clients[sender][1])
			del clients[sender]
