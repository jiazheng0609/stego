#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
	unsigned char ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
	unsigned char ether_shost[ETHER_ADDR_LEN];	/* Source host address */
	unsigned short ether_type;	/* IP? ARP? RARP? etc */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
	unsigned char ip_vhl;	/* version << 4 | header length >> 2 */
	unsigned char ip_tos;	/* type of service */
	unsigned short ip_len;	/* total length */
	unsigned short ip_id;	/* identification */
	unsigned short ip_off;	/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	unsigned char ip_ttl;	/* time to live */
	unsigned char ip_p;	/* protocol */
	unsigned short ip_sum;	/* checksum */
	struct in_addr ip_src, ip_dst;	/* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport;	/* source port */
	unsigned short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	unsigned char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	unsigned short th_win;	/* window */
	unsigned short th_sum;	/* checksum */
	unsigned short th_urp;	/* urgent pointer */
};

struct sniff_udp {
	unsigned short sport;
	unsigned short dport;
	unsigned short len;
	unsigned short cksum;
};

#define MAX_PACKET_SIZE 65535

int fileSize(FILE * fptr)
{
	if (fptr == NULL) {
		printf("error");
		return -1;
	}

	fseek(fptr, 0L, SEEK_END);
	int ans = ftell(fptr);
	rewind(fptr);
	return ans;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	struct pcap_pkthdr header;
	const unsigned char *packet;
	int hide_cnt = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <input_pcap_file>\n", argv[0]);
		return 1;
	}

	/* Open secret file */
	FILE *fptr;
	unsigned short tmp;
	char *sec_buffer;

	fptr = fopen("out.txt", "w");
	if (fptr == NULL) {
		fprintf(stderr, "Error : could not open file\n");
		return 1;
	}

	/* Open input PCAP file for reading */
	pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
		return 1;
	}

	/* Loop through the packets */
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		struct sniff_ethernet *ethernet;	/* The ethernet header */
		struct sniff_ip *ip;	/* The IP header */
		struct sniff_tcp *tcp;	/* The TCP header */
		struct sniff_udp *udp;
		unsigned char *payload;	/* Packet payload */
		unsigned short read_bytes;
		char first_byte;
		char second_byte;

		unsigned int size_ip;
		unsigned int size_tcp;

		ethernet = (struct sniff_ethernet *)(packet);
		ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip) * 4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n",
			       size_ip);
			return 1;
		}

		udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);

		/* Read from source port */

		if (udp->sport == htons(13579)) {
			break;
		} else {
			read_bytes = ntohs(udp->sport);
			second_byte = read_bytes >> 8;
			first_byte = read_bytes & 255;
			fwrite(&first_byte, 1, 1, fptr);
			fwrite(&second_byte, 1, 1, fptr);
		}

	}
	printf("Secret file extracted at: out.txt\n");

	/* Close the file */
	pcap_close(pcap);
	fclose(fptr);

	return 0;
}
