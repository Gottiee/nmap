# nmap

## Struct

```c
#define ALL 0
#define SYN 1
#define NULL 2
#define ACK 3
#define FIN 4
#define XMAS 5
#define UDP 6

#define OPEN 1
#define CLOSE 2
#define FILTERED 3

struct info
{
    // nbr de thread
    int thread; // default 0
    int scan_type; //default 0 : else define type
};

typedef struct s_scan_port
{
    int port_nbr;
    char *service;
    // tableau pour les differents state (selon le type de scan)
    int state[7];
} t_scan_port;

typedef struct s_info_port
{
    int nbr_of_port_scan;
    int to_scan[1024];
} t_info_port;

typedef struct s_host
{
    struct host *next;
    struct s_port port_tab[1024]
} t_host;
```

## Flux

- Parsing
    - commande
    - file ? 
    - option 
        - return un tableau de host /ip / NULL
        - sauf si option help
- dns resolution
- while (host /ip)
// multithreader la transformation en sockaddr_in et le ping de port
- transform en sockadrr in
    - fonctionne : en envoie les requete poru tester les ports
        - ping pour voir s'ils sont up
        - si on arrive a ping
            - un thread par port (opti possbile)
            - faire touts les types de scan si demandee (SYN, XMAS ..)
            - scan (open / close / filtered)
                -  si open (essaie de determiner le service)
    - sinon: on boucle    
- print


- host / ip [45];
    - tableau de sock addrin ? zzz


### Pseudo code

```c
char **
'\0'

test '\0' google.com NULL

google.com "\0"
```


```c
port.service = return_string();
 
char *return_string()
{
    if (HTTP)
        return "http";
}
```

## TODO

- memoire
- free les malloc / la list chainee dans le fatalerror/ perror
- valrind

-parsing
	- nb_retries false opt non detectee

- passer info en global
- options dans info


Options:
-Pn : enlever le ping x
-iR <nbr>: choose random target
--max-retries <nbr>: Caps number of port scan proberetransmissions. x
-e <iface>:  Use specified interface
--ttl <val>: Set IP time-to-live field x