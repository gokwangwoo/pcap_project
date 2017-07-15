#define ETHER_ADDR_LEN	6

#include <pcap.h>
#include <net/ethernet.h>
#include <stdio.h>
struct sniff_ethernet {
	u_char h_dest[ETHER_ADDR_LEN]; /* Destination host address */
	u_char h_source[ETHER_ADDR_LEN]; /* Source host address */
	u_short h_proto; /* IP? ARP? RARP? etc */
};


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ethernet_header(const u_char *Buffer, int Size);
int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

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
		//while(1){
		/* Grab a packet */
		//packet = pcap_next(handle, &header);
		/* Print its length */
		//printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
		//pcap_close(handle);
		//return(0);
		//}
		pcap_loop(handle, -1, process_packet, NULL);
}
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	print_ethernet_header(buffer, size);
}
void print_ethernet_header(const u_char *Buffer, int Size)
{
     //struct ethhdr *eth = (struct ethhdr *)Buffer;
     struct sniff_ethernet *eth = (struct sniff_ethernet *)Buffer;

     printf("\n");
     printf("Ethernet Header\n");
     printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4], eth->h_dest[5]);
     printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3], eth->h_source[4], eth->h_source[5]);
     printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);

}



