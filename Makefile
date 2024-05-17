stego: hide-udp-srcport extract-udp-srcport

extract-udp-srcport: extract-udp-srcport.c
	gcc -o extract-udp-srcport extract-udp-srcport.c -lpcap

hide-udp-srcport: hide-udp-srcport.c
	gcc -o hide-udp-srcport hide-udp-srcport.c -lpcap
	
