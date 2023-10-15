#define APP_NAME		"TCP Syn Flood Defence"
#define APP_DESC		"Read the TCP Syn and IPs"
#define APP_COPYRIGHT	"No Copyright"
#define APP_DISCLAIMER	"GoodBye Attackers"

#include "../incs/ip_container.h"
#include "../incs/ip_headers.h"

/* app name/banner */
void print_app_banner(void) 
{
	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
	return;
}

/* print help text */
void print_app_usage(void) 
{
	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");
	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	static int count = 1;                   /* packet counter */

	/* get the time of first packet */
	if (count == 1) 
	{
		time(&table_round);
	}

	// boolean value for start dropping (0 not drop, 1 drop)
	static char ip_can_drop = 0;
	
	/* declare pointers to packet headers */
	const struct ethernet_header *ethernet;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct tcp_header *tcp;            /* The TCP header */

	int size_ip;
	int size_tcp;

	/* if 1 minutes pass from (current packet time - first packet time) and ip_can_drop == 0 
		flush the TCPIP_REJECTED and set ip_can_drop 1*/
	if ( (header->ts.tv_sec - table_round) >= 60 && !ip_can_drop ) 
	{
		system("iptables -F TCPIP_REJECTED");
		ip_can_drop = 1;
	}
	
	/* define ethernet header */
	ethernet = (struct ethernet_header*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* Altough filter just bring TCP check one more time for TCP */
	if (ip->ip_p != IPPROTO_TCP)	
		return;

	/*get the last octet of the host ip with token*/
	char ipsrc_tmp[16];
	strcpy(ipsrc_tmp, inet_ntoa(ip->ip_src));
	char* token = strtok(ipsrc_tmp, ".");
	u_char c = 0;
	while (token) 
	{
		/* if last octet is reached*/
		if (c == 3) 
		{
			/* index of entry array is host IP number (hash with host IP)*/
			u_char index = atoi(token);
			ip_update (ip_list, index, inet_ntoa(ip->ip_src), header->ts.tv_sec, header->ts.tv_usec, ip_can_drop);
		}
		token = strtok(NULL, ".");
    	c++;
	}
	
	//printf("   Protocol: TCP\n");

	//printf("\nPacket number %d:\n", count);
	count++;

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* define/compute tcp header offset */
	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) 
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	//printf("   TCP Flag: %d\n", ntohs(tcp->th_flags));
	//printf("   sequence: %d\n", ntohs(tcp->th_seq));
	//printf("   ack no: %d\n", ntohs(tcp->th_ack));
	return ;
}