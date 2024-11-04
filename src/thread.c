#include "../inc/nmap.h"

void *routine(void *index)
{
    printf("Routine from thread %d\n", *(int *)index);
    return NULL;
}

void create_thread()
{
    pthread_t tid[3];

    for (int i = 0; i < 3; i ++)
        pthread_create(&tid[i], NULL, &routine, &i);
}