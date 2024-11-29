#include "../inc/nmap.h"


void alarm_handler(int sig)
{
	(void) sig;
	long int thread_tid = syscall(SYS_gettid);
	printf("main tid = %ld and local is %ld\n", g_main_tid, thread_tid);
	pcap_t **static_handle = get_handle();

	if (g_main_tid == thread_tid)
		pcap_breakloop(static_handle[0]);
	else
	{
		printf("alarm static_handle[%ld] = %p\n", thread_tid - g_main_tid - 1, static_handle[thread_tid - g_main_tid - 1]);
		pcap_breakloop(static_handle[thread_tid - g_main_tid - 1]);
	}
}

void timer_handler(int sig, siginfo_t *si, void *uc)
{
    t_thread_scan *scan = (t_thread_scan *)si->si_value.sival_ptr;
	(void)uc;
	(void)sig;
	int thread_id = si->si_value.sival_int;
    printf("Thread %d received its timer signal!\n", thread_id);

	printf("(%d) calling timer for handler *%p\n", scan->thread_it, scan->handle);
	pcap_breakloop(scan->handle);
}