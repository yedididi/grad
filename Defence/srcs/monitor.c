#include "../incs/ip_container.h"
#include "../incs/list.h"

void    *monitor(void *argv)
{
    pcap_t *handle;
    int     num_packets;

    num_packets = 0;
    handle = (pcap_t *)argv;
    //loop
    pcap_loop(handle, num_packets, update_ll, NULL);
}

void    update_ll(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    t_ip_node   *node;
    t_ip_node   *next_node;
    time_t      after_min;
    
    sleep(60);
    time(after_min);
    node = head_ip;
    pthread_mutex_lock(head_ip->ip_mutex);
    while (node)
    {
        next_node = node->next_node;
        if (after_min - node->last_attack_time > 60)
            delete_node(head_ip, node->ip_address);
        node = next_node;
    }
    pthread_mutex_unlock(head_ip->ip_mutex);
}

void    end_thread(pthread_t monitoring_t, t_ip_node *head_ip)
{
    pthread_join(monitoring_t, NULL);
	pthread_mutex_destroy(&(head_ip->ip_mutex));
}