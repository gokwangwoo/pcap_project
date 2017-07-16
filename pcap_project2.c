#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET	14
#include <pcap.h>
#include <net/ethernet.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include <string.h> 
#include <stdio.h>
struct sniff_ethernet {
	u_char h_dest[ETHER_ADDR_LEN]; /* Destination host address */
	u_char h_source[ETHER_ADDR_LEN]; /* Source host address */
	u_short h_proto; /* IP? ARP? RARP? etc */
};

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)
struct sockaddr_in source,dest;
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ethernet_header(const u_char *Buffer, int Size);
void print_ip_header(const u_char *, int );
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
		const u_char *packet;		/* The actual packet */
		int size;
		
		u_char *buffer;

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


	while (pcap_next_ex(handle, &header, &packet) >= 0)
	{
		//printf("header->len : %d\n", header->len);
		 size = header->len;
		//ethernet = (struct sniff_ethernet*)(packet);
		//ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		
		print_ethernet_header(buffer, size);
		//printf("src ip address: %s dest address: %s \n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
			
	}


}
void print_ethernet_header(const u_char *Buffer, int Size)
{
	
     struct sniff_ethernet *eth = (struct sniff_ethernet *)Buffer;
     
    


     printf("\n");
     printf("Ethernet Header\n");
     printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4], eth->h_dest[5]);
     printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3], eth->h_source[4], eth->h_source[5]);
     printf("   |-Protocol            : %d \n",(unsigned short)eth->h_proto);

     //struct sniff_ip *iph = (struct sniff_ip *)(Buffer + sizeof(struct eth));
     struct sniff_ip *iph = (struct sniff_ip *)(Buffer + sizeof(struct sniff_ethernet));

     unsigned short iphdrlen = iph->ip_len*4;
     
    
     //source.sin_addr.s_addr = iph->in_addr.ip_src;

     
     //memset(&source, 0, sizeof(source));
     //source.sin_addr.s_addr = iph->in_addr.ip_src;
     //memset(&inet_ntoa, 0, sizeof(inet_ntoa));
     //dest.sin_addr.s_addr = iph->in_addr.ip_dst;

      printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
     printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));
     
}




