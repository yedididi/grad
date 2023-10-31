#include "../incs/list.h"
#include "../incs/ip_container.h"

void	init_ip_list(t_ip_node *head_ip)
{
	head_ip = (t_ip_node *)malloc(sizeof(t_ip_node));
	if (head_ip == 0)
		exit(1);
	head_ip->count = 0;
    head_ip->ip_address = 0;
	head_ip->ts_index = 0;
	head_ip->is_rejected = 0;
	if (pthread_mutex_init(&(head_ip->ip_mutex), NULL) != 0)
		exit(1);
    head_ip->next_node = 0;
}

t_ip_node	*create_new_ipnode(char *ip_address, pthread_mutex_t ip_mutex)
{
	t_ip_node	*newnode;

	newnode = (t_ip_node *)malloc(sizeof(t_ip_node));
	if (newnode == 0)
		exit(1);
	newnode->count = 0;
    newnode->ip_address = ip_address;
	newnode->ts_index = 0;
	newnode->is_rejected = 0;
	newnode->ip_mutex = ip_mutex;
	return (newnode);
}

void	add_new_ipnode(char *ip_address, t_ip_node *head_ip)
{
	t_ip_node	*newnode;
	t_ip_node	*before_tail_node;

	newnode = create_new_ipnode(ip_address, head_ip->ip_mutex);
	newnode->next_node = NULL;
	before_tail_node = head_ip;
	while (1)
	{
		if (before_tail_node->next_node == 0)
			break ;
		before_tail_node = before_tail_node->next_node;
	}
	before_tail_node->next_node = newnode;
}

void	free_ipnode(t_ip_node *node)
{
	if (node == NULL)
		return ;
    free(node->ip_address);
	free(node);
	node = NULL;
}

t_ip_node	*search_ipnode(char *ip_address, t_ip_node *head_ip)
{
	t_ip_node	*node;

	node = head_ip;
	while (node)
	{
		if (strncmp(ip_address, node->ip_address, strlen(ip_address)) == 0)
			return (node);
		node = node->next_node;
	}
	return (NULL);
}

void	delete_node(t_ip_node *env_head, char *ip_address)
{
	t_ip_node	*node;
	t_ip_node	*prev_node;
	t_ip_node	*real_head;

	real_head = env_head;
	node = env_head;
	prev_node = NULL;
	while (node)
	{
		if (strncmp(ip_address, node->ip_address, strlen(node->ip_address)) == 0)
		{
			if (prev_node == NULL)
				real_head->next_node = node->next_node;
			else
				prev_node->next_node = node->next_node;
			free_ipnode(node);
			return ;
		}
		prev_node = node;
		node = node->next_node;
	}
}