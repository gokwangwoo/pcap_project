#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET	14
#define INET_ADDRSTRLEN	16
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>
struct sniff_ethernet {
	//u_char h_dest[ETHER_ADDR_LEN]; /* Destination host address */
	//u_char h_source[ETHER_ADDR_LEN]; /* Source host address */
	//u_short h_proto; /* IP? ARP? RARP? etc */

	uint8_t h_dest[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t h_source[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t h_proto; /* IP? ARP? RARP? etc */
};

struct sniff_ip {
	//u_char ip_vhl;		/* version << 4 | header length >> 2 */
	//u_char ip_tos;		/* type of service */
	//u_short ip_len;		/* total length */
	//u_short ip_id;		/* identification */
	//u_short ip_off;		/* fragment offset field */
	uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
	uint8_t ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;		/* identification */
	uint16_t ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	//u_char ip_ttl;		/* time to live */
	//u_char ip_p;		/* protocol */
	//u_short ip_sum;		/* checksum */
	uint8_t ip_ttl;		/* time to live */
	uint8_t ip_p;		/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

struct sockaddr_in source,dest;

typedef u_int tcp_seq;

struct sniff_tcp {
        //u_short th_sport;               /* source port */
	   uint16_t th_sport;
        //u_short th_dport;               /* destination port */
	   uint16_t th_dport;
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        //u_char  th_offx2;               /* data offset, rsvd */
	   uint8_t  th_offx2;
	   #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        //u_char  th_flags;
	   uint8_t th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        //u_short th_win;                 /* window */
        //u_short th_sum;                 /* checksum */
        //u_short th_urp;                 /* urgent pointer */

	   uint16_t th_win;                 /* window */
        uint16_t th_sum;                 /* checksum */
        uint16_t th_urp;                 /* urgent pointer */
};

void print_packet_data(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *Buffer;		/* The actual packet */
		int size;
		int packetnumber = 10;
		u_char *buffer;
		int res;

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		//handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

	const struct sniff_ip *ip;
	while((res = pcap_next_ex(handle, &header, &Buffer))>=0){
			if(res == 0)
				continue;

			print_packet_data(buffer, header, Buffer);
		}
	

        //pcap_loop(handle, packetnumber, print_packet_data, NULL);


}

    
    
	
void print_packet_data(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	
	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	///inet_ntop
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	///
	int size_ip;
	int size_tcp;
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
     	printf("\n");
     	printf("Ethernet Header\n");
     	printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernet->h_dest[0] , ethernet->h_dest[1] , ethernet->h_dest[2] , ethernet->h_dest[3] , ethernet->h_dest[4], ethernet->h_dest[5]);
     	printf("|-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernet->h_source[0] , ethernet->h_source[1] , ethernet->h_source[2] , ethernet->h_source[3], ethernet->h_source[4], ethernet->h_source[5]);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("IP_HL: %d, IP_V: %d\n", IP_HL(ip), IP_V(ip));
	/* print source and destination IP addresses */
	//printf("			Source IP: %s\n", inet_ntop(AF_INET, &(ip->ip_src), sourceIp, 16));
	printf("			Source IP: %s\n", inet_ntop(AF_INET, &(ip->ip_src), sourceIp, INET_ADDRSTRLEN));
	//printf("       Source IP: %s\n", inet_ntoa(ip->ip_src));
	//printf("			Destination IP: %s\n", inet_ntop(AF_INET, &(ip->ip_dst), destIp, 16));
	printf("			Destination IP: %s\n", inet_ntop(AF_INET, &(ip->ip_dst), destIp, INET_ADDRSTRLEN));
	//printf("       Destionation IP: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			return;
		case IPPROTO_ICMP:
			return;
		case IPPROTO_IP:
			return;
		default:
			return;
	}
	
	
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

return;
}
    
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch); //hex data transform to Capital letter and if data null print 0(데이터가 없으면 0을 출력한다 ex) 04)이런식으로
		//printf("%x", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload; //인쇄가능 즉 character문자 출력을 해주고 아닌 경우는 . 으로 처리
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}



