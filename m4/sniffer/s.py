import socket
import struct
import textwrap

PROTOCOLS = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 9: 'IGP', 17: 'UDP'}
BUF = 65535

def textwrapping(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix+line for line in textwrap.wrap(string, size)])

def parse_mac(mac):
	byte_str = map('{:02x}'.format, mac)
	return ':'.join(byte_str).upper()

def tcp_parse(packet):
	res = {}
	(res['src_port'], res['dest_port'], res['sequence'], res['acknowledgment'], ORF) = struct.unpack('! H H L L H', packet[:14])
	offset = (ORF >> 12) * 4
	res['flag_urg'] = (ORF & 32) >> 5
	res['flag_ack'] = (ORF & 16) >> 4
	res['flag_psh'] = (ORF & 8) >> 3
	# ...
	return packet[offset:], res

def udp_parse(packet):
	res = {}
	(res['src_port'], res['dest_port'], res['size']) = struct.unpack('! H H 2x H', packet[:8])
	return packet[4:], res

def ether_frame(packet):
	res = {}
	(dest, src, ether_type) = struct.unpack('! 6s 6s H', packet[:14])
	res['destination_mac'] = parse_mac(dest)
	res['src_mac'] = parse_mac(src)
	res['ethernet_type'] = socket.htons(ether_type)
	return packet[14:], res

def icmp_parse(packet):
	res = {}
	(res['type'], res['code'], res['checksum']) = struct.unpack('! B B H', raw_data[:4])
	return packet[4:], res

def header_parse(packet):
	res = {}
	version_header = packet[0]
	res['version'] = version_header >> 4
	header_length = (version_header & 15) * 4
	(res['ttl'], pro, src, target) = struct.unpack('! 8x B B 2x 4s 4s', packet[:20])
	res['src_ip'] = '.'.join(map(str, src))
	res['destination_ip'] = '.'.join(map(str, target))
	res['header_length'] = str(header_length) + 'byte'
	try:
		res['destination_host'] = socket.gethostbyaddr(res['destination_ip'])[0]
	except:
		pass
	try:
		res['src_host'] = socket.gethostbyaddr(res['src_ip'])[0]
	except:
		pass
	res['protocol'] = PROTOCOLS.get(pro, 'unknown')
	return packet[header_length:], res


with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as conn:
	conn.bind(('wlan0', 0x0003))
	while True:
		recv = conn.recvfrom(BUF)
		(raw_data, ether) = ether_frame(recv[0])
		print('Ethernet frame:')
		for i in ether:
			print(f"\t{i}: {ether[i]}")
		print('Header:')
		(raw_data, header) = header_parse(raw_data)
		for i in header:
			print(f"\t{i}: {header[i]}")
		# if header['protocol'] == 'TCP':
		# 	data, tcp = tcp_parse(raw_data)
		# 	print('TCP:')
		# 	for i in tcp:
		# 		print(f"\t{i}: {tcp[i]}")
		# 	if len(data):
		# 		print('TCP data:')
		# 		if 80 in (tcp['src_port'], tcp['dest_port']):
		# 			try:
		# 				data = data.decode('u8')
		# 				for line in data.split('\n'):
		# 					print(f"\t{line}")
		# 			except:
		# 				print(textwrapping('\t', data))
		# 		else:
		# 			print(textwrapping('\t', data))
		# elif header['protocol'] == 'UDP':
		# 	(data, udp) = udp_parse(raw_data)
		# 	print('UDP:')
		# 	for i in udp:
		# 		print(f"\t{i}: {udp[i]}")
		# 	print('UDP data:')
		# 	print(textwrapping('\t', data))
		# elif header['protocol'] == 'ICMP':
		# 	(data, icmp) = icmp_parse(raw_data)
		# 	print('ICMP:')
		# 	for i in icmp:
		# 		print(f"\t{i}: {icmp[i]}")
		# 	print('ICMP data:')
		# 	print(textwrapping('\t', data))
		# else:
		# 	print('Other protocols:')
		# 	print(textwrapping('\t', raw_data))
		# print('-'*40)