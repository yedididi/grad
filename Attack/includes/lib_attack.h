#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
 
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
        *((u_char*)&oddbyte) =* (u_char*)ptr;
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
    int flag=1;
    int counter=0;

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
                break ;
            }
        }
        else
        {
            flag = 0;
            break ;
        }
     }
     return (flag && counter == 4);
}

struct iphdr
{
    u_int   ip_hl:4,                /* header length */
	    ip_v:4;                     /* version */
    u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
    unsigned short check;
    in_addr_t saddr;
    in_addr_t daddr;
};

struct tcphdr_ 
{
	unsigned short  th_sport;       /* source port */
	unsigned short  th_dport;       /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	unsigned int    th_x2:4,        /* (unused) */
	    th_off:4;                   /* data offset */
	unsigned char   th_flags;
    int             fin;
    int             syn;
    int             rst;
    int             psh;
    int             ack;
    int             urg;
	unsigned short  th_win;         /* window */
	unsigned short  th_sum;         /* checksum */
	unsigned short  th_urp;         /* urgent pointer */
};