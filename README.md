# Sending-and-sniffing-ICMP-Echo

part 1: myping
	the program creates a raw socket and cooking an icmp header(checksum calcs included) we decided to send the 
	ping to 8.8.8.8 (google dns) as you can see in the wireshark output. google's server replied as expected.


part 2: sniffing
	after starting the sniffing we sent ping requests to google(8.8.8.8) and to the host machine
	(192.168.82.129) and managed to capture them with the sniffer program.
