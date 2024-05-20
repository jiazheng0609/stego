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

#define SIZE_UDP 8
#define MAX_PACKET_SIZE 65535

struct sniff_rtp {
#if RTP_BIG_ENDIAN
	unsigned int version:2;	/* protocol version */
	unsigned int p:1;	/* padding flag */
	unsigned int x:1;	/* header extension flag */
	unsigned int cc:4;	/* CSRC count */
	unsigned int m:1;	/* marker bit */
	unsigned int pt:7;	/* payload type */
#else
	unsigned int cc:4;	/* CSRC count */
	unsigned int x:1;	/* header extension flag */
	unsigned int p:1;	/* padding flag */
	unsigned int version:2;	/* protocol version */
	unsigned int pt:7;	/* payload type */
	unsigned int m:1;	/* marker bit */
#endif
	unsigned int seq:16;	/* sequence number */
	uint32_t ts;		/* timestamp */
	uint32_t ssrc;		/* synchronization source */
	uint32_t csrc[1];	/* optional CSRC list */
};

/* RTP Header Extension */
struct rtp_hdr_ext {
	uint16_t ext_type;	/* defined by profile */
	uint16_t len;		/* extension length in 32-bit word */
};

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
	unsigned int hide_cnt = 0;
	char bit_in_char = 0;
	int consec_zero = 0;

	if (argc != 3) {
		fprintf(stderr,
			"Usage: %s <input_pcap_file> <secret_file>\n",
			argv[0]);
		return 1;
	}

	/* Open secret file */
	FILE *fptr;
	unsigned char sec_buffer;
	unsigned int sec_file_size;

	fptr = fopen(argv[2], "w");
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

	sec_buffer = 0;
	/* Loop through the packets */
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		struct sniff_ethernet *ethernet;	/* The ethernet header */
		struct sniff_ip *ip;	/* The IP header */
		struct sniff_tcp *tcp;	/* The TCP header */
		struct sniff_udp *udp;
		struct sniff_rtp *rtp;
		struct rtp_hdr_ext *ext;
		unsigned char *payload;	/* Packet payload */

		unsigned int size_ip;
		unsigned int size_tcp;
		unsigned int size_udp;
		unsigned short size_udp_payload;
		unsigned int size_rtp_h;
		unsigned int size_rtp_ext;
		unsigned int last_byte_pos;

		ethernet = (struct sniff_ethernet *)(packet);
		ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip) * 4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n",
			       size_ip);
			return 1;
		}

		udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
		// printf("%s:%d\t-> %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->sport), inet_ntoa(ip->ip_dst), ntohs(udp->dport));

		size_udp_payload = ntohs(udp->len);

		rtp =
		    (struct sniff_rtp *)(packet + SIZE_ETHERNET + size_ip +
					 SIZE_UDP);
		if (rtp->version == 2 && rtp->pt == 8) { /* We only deal with RTP v2 and G.711 */
			size_rtp_h = 12 + rtp->cc * 4;

			if (rtp->x) {	/* header extension */
				ext =
				    (struct rtp_hdr_ext *)(packet +
							   SIZE_ETHERNET +
							   size_ip + SIZE_UDP +
							   size_rtp_h);
				size_rtp_ext = ntohs(ext->len);
			} else {
				size_rtp_ext = 0;
			}

			payload =
			    (unsigned char *)(packet + SIZE_ETHERNET + size_ip +
					      SIZE_UDP + size_rtp_h +
					      size_rtp_ext);
			last_byte_pos =
			    size_udp_payload - size_rtp_h - size_rtp_ext - 9;

			printf
			    ("rtp version %d, payload type %d, seq %u, ts %lu, ssrc=0x%lX, payload firstb %x, lsb %x\n",
			     rtp->version, rtp->pt, ntohs(rtp->seq),
			     (unsigned long)ntohl(rtp->ts),
			     (unsigned long)ntohl(rtp->ssrc), payload[0],
			     payload[last_byte_pos]);
			

			for (int i = 0; i < last_byte_pos; i++) {
				printf("byte %d bit %x zeros %d\n", i, (payload[i]&1), consec_zero);
				if (((payload[i] & 1) == 0) && (consec_zero == 7)) {
					consec_zero++;
					printf("finish!\n");
					break;
				} 
				else if ((payload[i] & 1) == 0)  {
					consec_zero++;
				} else {
					consec_zero = 0;
				}
				sec_buffer = sec_buffer | (unsigned char)((payload[i] & 1) << bit_in_char);
				bit_in_char--;
				if (bit_in_char == 8) {
					fwrite(&sec_buffer, 1, 1, fptr);
					bit_in_char = 0;
					sec_buffer = 0;
				}
			if (consec_zero >= 7) {
				return 0;
				break;
			}
				 
			} 
		}

	}

	/* Close the file */
	fclose(fptr);
	pcap_close(pcap);

	return 0;
}
