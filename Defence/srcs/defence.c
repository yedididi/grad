#include "../incs/ip_headers.h"
#include "../incs/ip_container.h"

/* WARNING you can uncomment the printf functions for debug purpose
	in the real time not uncomment them because when printing the system can miss some packets*/

int main(int argc, char **argv) 
{
	/* flush the INPUT chain to prevent duplicate entries*/
	system("iptables -F INPUT");

	/* enable ssh port so if your IP is blocked from connection you can still connect to server with ssh*/
	system("iptables -I INPUT -p tcp --dport 22 -j ACCEPT");

	/*new chains for reject and drop*/
	system("iptables -N TCPIP_REJECTED");
	system("iptables -N TCPIP_DROPPED");

	/* adding subchains to INPUT chain*/
	system("iptables -A INPUT -j TCPIP_REJECTED");
	system("iptables -A INPUT -j TCPIP_DROPPED");
	
	/* flush chains*/
	system("iptables -F TCPIP_REJECTED");
	system("iptables -F TCPIP_DROPPED");

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "dst host 10.20.40.31 and port 8080 and ip and (tcp[tcpflags] & (tcp-syn) != 0)";		/* filter expression for pcap compile */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0;			/* number of packets to capture */

	ip_list = ip_init();	/* ip list initialization*/

	print_app_banner();

	/* find a capture device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) 
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	ip_free(ip_list);

	printf("\nCapture complete.\n");

	return 0;
}

