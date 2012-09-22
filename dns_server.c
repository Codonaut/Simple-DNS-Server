#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <execinfo.h>
#include <signal.h>

typedef struct sockaddr_in sockaddr_in;
typedef struct hostent hostent;

/* Prints stack trace upon segmentation fault */
void handler(int sig) {
    void *array[10];
    size_t size;
    
    size = backtrace(array, 10);
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, 2);
    exit(1);
}

/* Creates, and binds a UDP socket that is then returned */
int open_udp_socket() {
    
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    printf("after creation\n");
    if (udp_sock < 0) {
        perror("ERROR OPENING SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    sockaddr_in *addr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
    memset((char *)addr, 0, sizeof(sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(0);
    if (bind(udp_sock, (struct sockaddr *)addr, sizeof(sockaddr_in)) < 0) {
        perror("ERROR BINDNIG SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    return udp_sock;
}

void paddr(unsigned char *a) {
        printf("%d.%d.%d.%d\n", a[0], a[1], a[2], a[3]);
}


int main(int argc, char** argv) {
    
    setbuf(stdout, NULL);
    signal(SIGSEGV, handler);   // install our handler
    
    int udp_sock = open_udp_socket();
    
    hostent *hp;
    char *host = "www.google.com";
    hp = gethostbyname(host);
    
    if (!hp) {
        perror("ERROR IN OBTAINING ADDRESS OF HOST\n TERMINATING PROGRAM\n");
        return 1;
    } 
    
    int i;
    for (i = 0; hp->h_addr_list[i] != 0; i++)
        paddr((unsigned char*) hp->h_addr_list[i]);
    
    return 0;
}
