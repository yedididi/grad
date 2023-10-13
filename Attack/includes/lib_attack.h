#ifndef LIB_ATTACK_H
#define LIB_ATTACK_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>   //provides declarations for socket programramming 
#include <stdlib.h>       //for exit(0);
#include <errno.h>        //For errno - the error number
#include <netinet/tcp.h>  //Provides declarations for tcp header
#include <netinet/ip.h>   //Provides declarations for ip header
#include <time.h>	 //In case of using duration.
#include <unistd.h>	 //To avoid unnecessary warnings after compilation 
#include <arpa/inet.h>    //To avoid unnecessary warnings after compilation
#include <ctype.h>

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

unsigned short  csum(unsigned short *ptr,int nbytes);
int             check_IP(char *IP);
void            accept_info(FILE *interfaceFile, char *dIP, int *destPort);
void            fill_struct(struct sockaddr_in sin, struct iphdr *iph, struct tcphdr *tcph, struct pseudo_header psh, int destPort, char *dIP, char *source_ip, char *datagram, int sourcePort);


#endif