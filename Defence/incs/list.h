#ifndef LIST_H
#define LIST_H

#include <string.h>

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
	u_char              ts_index;	/* current index of timestamps circular array */
	u_char              is_rejected;	/*if the ip is rejected then 1, not rejected 0, blacklist 2 */
    struct s_ip_node    *next_node;
} t_ip_node;

void	    init_ip_list(t_ip_node *head_ip);
t_ip_node	*create_new_ipnode(char *ip_address);
void	    add_new_ipnode(char *ip_address, t_ip_node *head_ip);
void	    free_ipnode(t_ip_node *node);
t_ip_node	*search_ipnode(char *ip_address, t_ip_node *head_ip);
void	    delete_node(t_ip_node *env_head, char *ip_address);

#endif