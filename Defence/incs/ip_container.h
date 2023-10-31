#ifndef IP_CONTAINER_H
#define IP_CONTAINER_H

#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "list.h"

// /* seconds and microseconds of the entry*/
// struct IP_timestamp {
// 	long int sec;
// 	long int usec;
// };

// #ifndef IP_ENTRY_H
// #define IP_ENTRY_H
// struct IP_entry {
// 	u_int count;	/* how many packets are received from this IP*/
// 	struct IP_timestamp timestamps[50];		/* circular array contains the arrival time of last 50 packets from this IP */
// 	u_char ts_index;	/* current index of timestamps circular array */
// 	u_char is_rejected;	/*if the ip is rejected then 1, not rejected 0, blacklist 2 */
// };
// #endif

#define IP_ARR_SIZE 254	/* 254 host ip 10.20.40.* (0 and 255 excluded)*/ 

/* create new IP_entry in ip_list */
struct IP_entry** ip_init ();

/* Reset the ip_entry */
void ip_reset (struct IP_entry **ip_list, u_char index);

// t_ip_node *head_ip;

// /* update the entry values  in the specific index*/
// void ip_update(t_ip_node *head_ip, u_char ip_address, char* source_ip, long int sec, long int usec, char can_drop);

// /* deallocation of the memory spaces */
// void ip_free(t_ip_node *head_ip);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

void    *monitor(void *argv);
void    update_ll(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void    end_thread(pthread_t monitoring_t, t_ip_node *head_ip);

#endif