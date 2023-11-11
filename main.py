from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def scan(ip):
	# Create an ARP request packet
	arp_request = ARP(pdst=ip)

	# Create an Ethernet frame to contain the ARP request
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")

	# Combine the Ethernet frame and ARP request
	packet = ether / arp_request

	# Send the packet and receive the response
	result = srp(packet, timeout=3, verbose=0)[0]

	# Extract the IP and MAC addresses from the response
	devices = []
	for sent, received in result:
		devices.append({'ip': received.psrc, 'mac': received.hwsrc})

	return devices


def print_result(devices):
	print("IP Address\t\tMAC Address")
	print("-----------------------------------------")
	for device in devices:
		print(f"{device['ip']}\t\t{device['mac']}")


if __name__ == "__main__":
	# Replace '192.168.1.1/24' with your network range
	target_ip = "192.168.1.1/24"

	devices_list = scan(target_ip)
	print_result(devices_list)
