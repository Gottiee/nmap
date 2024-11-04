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

struct port
{
    int port_nbr;
    char *service;
    int state; // open / close /filtered
}

struct host
{
    int nbr_of_port_scan;
    struct host *next;
    struct port port_tab[1024]

};
```

## Flux

- Parsing
    - commande
    - file ? 
    - option 
        - return un tableau de host /ip / NULL
        - sauf si option help
- dns resolution
    - remplace les host par des ip
    - si resoltuion a rater, on remplace la string par '\0'
        - return tableau d'ip
- Iterer sur les ip et verifier que la string != '\0'
    - ping pour voir s'ils sont up
- si on arrive a ping
    - un thread par port (opti possbile)
    - faire touts les types de scan si demandee (SYN, XMAS ..)
    - scan (open / close / filtered)
        -  si open (essaie de determiner le service)
- print


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