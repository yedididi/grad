#ifndef LIST_H
#define LIST_H

#include <string.h>
#include <stdlib.h>

/* seconds and microseconds of the entry*/
struct IP_timestamp {
	long int sec;
	long int usec;
};

typedef struct s_ip_node
{
    u_int               count;	/* how many packets are received from this IP*/
    char                *ip_address;
	struct IP_timestamp timestamps[50];		/* circular array contains the arrival time of last 50 packets from this IP */
	time_t				last_attack_time;
	u_char              ts_index;	/* current index of timestamps circular array */
	u_char              is_rejected;	/*if the ip is rejected then 1, not rejected 0, blacklist 2 */
    pthread_mutex_t		ip_mutex;
	struct s_ip_node    *next_node;
} t_ip_node;

void	    init_ip_list(t_ip_node *head_ip);
t_ip_node	*create_new_ipnode(char *ip_address, pthread_mutex_t ip_mutex);
void	    add_new_ipnode(char *ip_address, t_ip_node *head_ip);
void	    free_ipnode(t_ip_node *node);
t_ip_node	*search_ipnode(char *ip_address, t_ip_node *head_ip);
void	    delete_node(t_ip_node *env_head, char *ip_address);
/* update the entry values  in the specific index*/
void ip_update(t_ip_node *head_ip, char *ip_address, char* source_ip, long int sec, long int usec, char can_drop);

/* deallocation of the memory spaces */
void ip_free(t_ip_node *head_ip);

#endif