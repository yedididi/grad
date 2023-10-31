#include "../incs/ip_container.h"
#include "../incs/list.h"

void ip_update(t_ip_node *head_ip, char *ip_address, char* source_ip, long int sec, long int usec, char can_drop) 
{
	/* increment the packet counter of specific entry*/
	t_ip_node	*attack_node;
	attack_node = search_ipnode(ip_address, head_ip);
	if (attack_node == NULL)
		add_new_ipnode(ip_address, head_ip);
	attack_node->count++;
	time(&(attack_node->last_attack_time));

	/* current index of timestamps array*/
	u_char curr_index = attack_node->ts_index;

	/* current timestamp of timestamps array */
	struct IP_timestamp *curr = &(attack_node->timestamps[curr_index]);
	curr->sec = sec;
	curr->usec = usec;

	/* next index timestamp of current timestamp*/
	struct IP_timestamp next = attack_node->timestamps[(curr_index + 1) % 50];

	/*This checks count > 50 and time difference < 3*/
	if ((curr->sec - next.sec) < 3)
	{
		/* if ip address is not rejected before then reject the IP address*/
		if (attack_node->is_rejected == 0)
		{
			/* make a system call for reject the IP address with TCP-RST*/
			char iptables_systemcall[100] = "iptables -t filter -A TCPIP_REJECTED -p tcp -s ";
			strcat(iptables_systemcall, source_ip);
			strcat(iptables_systemcall, " -j REJECT --reject-with tcp-reset");
			system(iptables_systemcall);

			/* ip address is rejected*/
			attack_node->is_rejected = 1;
		}
		/* if can_drop is 1 since 60 seconds has passed and if the ip address already rejected then drop the IP address */
		else if (can_drop && attack_node->is_rejected == 1)
		{
			/* make a systemcall for drop the IP address*/
			char iptables_systemcall[90] = "iptables -t filter -A TCPIP_DROPPED -p tcp -s ";
			strcat(iptables_systemcall, source_ip);
			strcat(iptables_systemcall, " -j DROP ");
			system(iptables_systemcall);

			/* ip address is dropped*/
			attack_node->is_rejected = 2;
		}
	}
	/* increment the index and get the modulo 50 */
	(attack_node->ts_index)++;
	(attack_node->ts_index) %= 50;
}

/* clear the IP list */
void ip_free(t_ip_node *head_ip) 
{
	t_ip_node *node;

	node = head_ip;
	if (node) 
	{
		free_ipnode(node);
		node = node->next_node;
	}
}
