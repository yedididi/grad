#define APP_NAME		"TCP Syn Flood Defence"
#define APP_DESC		"Read the TCP Syn and IPs"
#define APP_COPYRIGHT	"No Copyright"
#define APP_DISCLAIMER	"GoodBye Attackers"

#include "../incs/ip_container.h"

/* app name/banner */
void print_app_banner(void) 
{
	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

/* print help text */
void print_app_usage(void) {

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}