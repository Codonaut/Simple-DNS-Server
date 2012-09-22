#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

typedef struct sockaddr_in sockaddr_in;
typedef struct hostent hostent;

/* Creates, and binds a UDP socket that is then returned */
int open_udp_socket() {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("ERROR OPENING SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    sockaddr_in* addr;
    memset(addr, 0, sizeof(sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(0);
    if (bind(udp_sock, (struct sockaddr *)addr, sizeof(addr)) < 0) {
        perror("ERROR BINDNIG SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    return udp_sock;
}

int main(int argc, char** argv) {
    
    int udp_sock = open_udp_socket();
    
    
    return 0;
}
