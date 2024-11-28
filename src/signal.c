#include "../inc/nmap.h"

pcap_t **g_handle;

void alarm_handler(int sig)
{
	(void) sig;
	long int thread_tid = syscall(SYS_gettid);
	printf("main tid = %ld and local is %ld\n", g_main_tid, thread_tid);
	if (g_info->nb_thread == 0)
		pcap_breakloop(g_handle[0]);
	else if (thread_tid != g_main_tid)
		pcap_breakloop(g_handle[thread_tid - g_main_tid - 1]);
	else 
		printf("wtf %ld\n" ,thread_tid);

	// trouver comment faire pur que le thread principal catch pas le sigalarm de con stp elito
}