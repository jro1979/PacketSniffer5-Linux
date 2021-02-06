#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#define BUFF 80
#define PKT_BUFF 1000
/////////////////////////////////////////////////////////////////////
//
// Sniff5:  Packet sniffer console program for Linux.  
//	    Uses BPF filter strings and PCAP library to capture/print IP packets.
//	    Created for school project (SEED Labs).
//	    Other functions included to send spoofed packets. 
// Author:  Jeremiah Robinson 
// Date:    2/6/2021
//
//////////////////////////////////////////////////////////////////////
struct ipheader
{
	unsigned char iph_ihl:4, iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3, iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

struct ethheader
{
	unsigned char ether_dhost[6];
	unsigned char ether_shost[6];
	unsigned short int ether_type;
};
struct icmpheader
{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;    
};
typedef	unsigned char	u_char;


// Prints packet contents
void print_packet(const struct pcap_pkthdr *header, const unsigned char *packet)
{
	char packet_data[PKT_BUFF] = "";
	int limit = header->len < PKT_BUFF ? header->len : PKT_BUFF;
	int bytes = 0;
	const unsigned char *ptr = packet;
	puts("Printing packet data....");

	while (bytes++ < PKT_BUFF)
	{
		packet_data[bytes -1] = *ptr;
		ptr++;
	}
	unsigned char ch = '\0';
	for (int i=0; i<limit; i++)
	{
		ch = packet_data[i];
		if (isprint(ch))
		{printf("%c", ch);}
		else
		{printf("%02X", ch);}
	} 
	putchar('\n');
}

// Sends IP packet
void send_raw_ip_packet (struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}


//Uses a 32 bit accumulator (sum), adds sequential 16 bit words to it, and at end, 
//folds back all the carry bits from top 16 bits into the lower 16 bits.
unsigned short in_chksum (unsigned short *buff, int length)
{
    unsigned short *w = buff;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -=2;
    }
    // treat odd byte at end, if any
    if (nleft == 1)
    {
        *(unsigned char *)(&temp) = *(unsigned char *)w;
        sum += temp;    
    }
    //Add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); //add hi 16 to low 16
    sum += (sum >> 16);  // add carry
    return (unsigned short)(~sum);
}

// Constructs IP packet
void build_packet (struct ipheader *og_packet)
{
	char buffer[1500];
    memset(buffer, 0, 1500);

    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; //8 is request, 0 is reply
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_chksum((unsigned short *)icmp, sizeof(struct icmpheader));
	struct ipheader *ip = (struct ipheader *) buffer;
    	ip->iph_ver = 4;
    	ip->iph_ihl = 5;
    	ip->iph_ttl = 20;
    	ip->iph_sourceip = og_packet->iph_destip;  //or use: = inet_addr("1.2.3.4");
    	ip->iph_destip = og_packet->iph_sourceip;  //or use: = inet_addr("10.0.2.69");
    	ip->iph_protocol = IPPROTO_ICMP;
    	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    	send_raw_ip_packet(ip);
}
//  Determines packet type: TCP/UDP/ICMP
void got_packet(u_char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{	
	//puts("Entering got_packet() function...\n");
	struct ethheader *eth = (struct ethheader *)packet;

	if (args[0] == 'y')
	{ print_packet(header, packet);	} 
	
	if (ntohs(eth->ether_type) == 0x0800) 
	{
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("To:   %s\n", inet_ntoa(ip->iph_destip));
		switch(ip->iph_protocol) 
		{
			case IPPROTO_TCP:
				printf("Protocol: TCP\n\n");
				return;
			case IPPROTO_UDP:
				printf("Protocol: UDP\n\n");
				return;
			case IPPROTO_ICMP:
				printf("Protocol: ICMP\n\n");
				build_packet(ip); //builds & sends out a spoofed reply 
				return;
			default:
				printf("Protocol: Others\n\n");	
				return;
		}
	}
	
}
// Reads input from user
int safeReadInt(const char* prompt)
{
	int number = 0;
	int ok = 0;
	do
	{
		puts(prompt);
		if (scanf("%d", &number) == 1)
		{ok = 1;}
		while (getchar() != '\n')
			;
	} while (!ok);
	return number;
}

int main(int argc, char *argv[])
{
	
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[BUFF] = "";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	int count =0;
	

	puts("Enter your BPF filter string: (ex: src host 192.168.1.1) (ex: icmp[icmptype] == icmp-echo) \n");
	fgets(filter_exp, BUFF, stdin);
	printf("You entered: %s\n", filter_exp);

	count = safeReadInt("How many packets do you want to capture? (Use -1 for infinite)\n");	
	printf("Ok, will capture %d packets \n", count);

	dev = pcap_lookupdev(errbuf);
	
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	else {printf("SUCCESS! Found device: %s \n", dev);}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net =0;
		mask=0;
	}
	else {puts("SUCCESS! Got netmask for device \n");}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	else {printf("SUCCESS: pcap_open_live() opened handle.\n");}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	}
	else {puts("SUCCESS! Compiled filter expression OK.\n");}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	}
	else {puts("SUCCESS! Installed the filter OK.\n");}
	puts("Print packet data? \n");
    char print = getchar();
	pcap_loop(handle, count, (pcap_handler)got_packet, (u_char *)&print);
	puts("Thank you, please come back for more\n");
	pcap_close(handle);
	return(0);
}

