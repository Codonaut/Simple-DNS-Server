

#include "dns_server.h"
#include <arpa/inet.h>

#define PORT 1153
#define BUFSIZE 2048

/*
*** TODO ***
* 1) Close socket
*
* QUESTION ***
* 1) Should the query type be 1?
* 2) No hosts file on site
* /

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
    //printf("after creation\n");
    if (udp_sock < 0) {
        perror("ERROR OPENING SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    return udp_sock;
}

void paddr(unsigned char *a) {
    printf("%d.%d.%d.%d\n", a[0], a[1], a[2], a[3]);
}


/* Returns a bit mask to retrieve the 0-indexed bits between lobit and hibit 
 * by using an & operation on the desired byte. */
int get_bitmask(int lobit, int hibit) {
    int mask = 0;
    int i;
    for (i=lobit; i<=hibit; i++)
        mask += (1 << i);
    return mask;
}


/* Bind the socket, and return the sockaddr_in associated with it */
sockaddr_in* bind_udp_socket(int udp_sock) {
    sockaddr_in *addr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
    memset((char *)addr, 0, sizeof(sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(PORT);
    if (bind(udp_sock, (struct sockaddr *)addr, sizeof(sockaddr_in)) < 0) {
        perror("ERROR BINDNIG SOCKET\nTERMINATING PROGRAM\n");
        exit(1);
    }
    
    return addr;
}


void parse_dns(char* msg, int recvlen, int socket, struct sockaddr* address, HostNode* list) {
    int* msg_len = &recvlen;
    dns_header* header = parse_header(msg);
    //print_header(header);
    dns_question* query = parse_queries(msg, header->qu_count);

    char* addr = getAddress(list, query->qnames);
    if (addr != NULL) {
        int *addr_int = (int*) malloc(sizeof(int));
        inet_pton(AF_INET, addr, addr_int);
        msg = attach_answer(msg, header, query, msg_len, *addr_int);
    } else
        modify_header_failure(header);

    sendto(socket, msg, *msg_len, 0, address, sizeof(struct sockaddr_in));
}


void modify_header_failure(dns_header* header) {
    header->rcode = 3;
}

// Modify the DNS Header to represent the needed values for an answer
void modify_header(dns_header* header, char* msg) {
    header->qr = 1;
    header->aa = 1;
    header->tc = 0;
    header->ra = 0;
    header->rcode = 3;
    header->an_count = htons(1);
}

// Attach answer to the msg, and returns
char* attach_answer(char* msg, dns_header* header, dns_question* question, int* msg_len, int addr) {
    modify_header(header, msg);
    int i;
    short type = htons(1);
    short class = htons(1);
    int ttl = htonl(86400);
    short rdlength = htons(4);
    int rdata = addr;


    int answer_len = question->qname_len + 14;
    char* answer = (char *) malloc(sizeof(char) * answer_len);
    
    for (i=0; i<question->qname_len; i++) {
        answer[i] = question->qname[i];
    }

    memcpy(answer + question->qname_len, &type, 2);
    memcpy(answer + question->qname_len + 2, &class, 2);
    memcpy(answer + question->qname_len + 4, &ttl, 4);
    memcpy(answer + question->qname_len + 8, &rdlength, 2);
    memcpy(answer + question->qname_len + 10, &rdata, 4);

    char* new_msg = (char*) malloc(*msg_len + answer_len);
    memset(new_msg, 0, *msg_len + answer_len);
    memcpy(new_msg, msg, *msg_len);

    int j = *msg_len;
    int total = *msg_len + answer_len;
    for (j; j < total; j++)
        new_msg[j] = answer[j-*msg_len];

    *msg_len = *msg_len + answer_len;
    return new_msg;
}


void print_header(dns_header* head) {
    printf("id: %d\nrd: %d\ntc: %d\nopcode: %d\nqr: %d\nqu_count: %d\n", head->id, head->rd, head->tc, head->opcode, head->qr, head->qu_count);
}


dns_question* parse_queries(char* msg, int qu_count) {
    dns_question* queries = (dns_question *) malloc(sizeof(dns_question) * qu_count);
    int pos, j = 0;
    int qu_offset = 12;     // Offset in message of start of each message(defaults to 12, position of first query)
    int seg_size = 0;       // Size of domain name segment
    int qu_snagged = 0;
    char* qu_name = (char *) malloc(sizeof(char));   // malloc space for the null terminating character
    int qu_name_size = 0;   // Size in bytes of the query name
    int last_write_index = 0;   // Index of the last write into qu_name

    
    for (pos=qu_offset; qu_snagged < ntohs(qu_count); pos++) {
        if (msg[pos] == 0) {

            qu_name = (char*) realloc(qu_name, sizeof(char) * (pos + 1));
            for (j=0; j<pos; j++)
                qu_name[j] = msg[qu_offset + j];
            qu_name_size = pos - qu_offset - 1;
            char *qnames = (char*) malloc(qu_name_size+1);
            for (j=0; j<qu_name_size; j++) {
                qnames[j] = qu_name[j+1];
                if (qu_name[j+1] < 65)
                    qnames[j] = '.';
            }
            qnames[qu_name_size+1] = '\n';
            (queries + qu_snagged)->qtype = msg[qu_offset + pos + 1] + msg[qu_offset + pos + 2];
            (queries + qu_snagged)->qclass = msg[qu_offset + pos + 3] + msg[qu_offset + pos + 4];
            (queries + qu_snagged)->qname = qu_name;
            (queries + qu_snagged)->qname_len = qu_name_size + 2;   // Add two for the leading number and trailing 0
            (queries + qu_snagged)->qnames = qnames;
            qu_snagged++;   
        }
    }

    return queries;
}


dns_header* parse_header(char* msg) {
    dns_header* header = (dns_header *) malloc(sizeof(dns_header));
    header = (dns_header*) msg;
    return header;
}


HostNode* createLList(char* name, char* address) {
    HostNode* head = (HostNode*) malloc(sizeof(HostNode));
    head->next = NULL;
    head->name = name;
    head->address = address;
}


void addHost(HostNode* head, char* name, char* address) {
    
    if (head->name == NULL) {
        head->name = name;
        head->address = address;
        return;
    }

    HostNode* newNode = (HostNode*) malloc(sizeof(HostNode));
    newNode->next = NULL;
    newNode->name = name;
    newNode->address = address;
    HostNode* ptr = head;
    while (ptr->next != NULL) { ptr = ptr->next; }
    ptr->next = newNode;
    
}


char* getAddress(HostNode* head, char* name) {
    HostNode* ptr = head;

    // Search name is found or end of list
    while (ptr != NULL && strcmp(ptr->name, name) != 0)
        ptr = ptr->next;

    if (ptr == NULL)
        return NULL;

    return ptr->address;
}


void printList(HostNode* head) {
    HostNode* ptr = head;
    while (ptr != NULL) {
        printf("Host name: %s  Address: %s\n", ptr->name, ptr->address);
        ptr = ptr->next;
    }
}


void fillList(HostNode* head, FILE* hosts) {
    char c;
    int newline = 1;
    int reading_name = 0, reading_addr = 0;     // Set to 1 when  a name or addr is being read
    char *name, *addr;
    int name_bytesread = 0, addr_bytesread = 0;
    int space_hit = 0;
    while ((c = fgetc(hosts)) != EOF) {
        // If it is a comment or blank line then go to the next loop iteration
        if (c == '#') {
            gotoNextLine(hosts);
            newline = 1;
             // If end of file was reached then return, otherwise continue with next character
            if (hosts == NULL)
                return;
            else
                continue;
        } else if (c == '\n') {
            if (reading_addr == 1) {
                addr[addr_bytesread] = '\0';
                reading_addr = 0;
                addr_bytesread = 0;
                // Insert a new node
                addHost(head, name, addr);
            }
            newline = 1;
            continue;
        }

        if (c == ' ' || c == '\t') {
            space_hit = 1;
            if (reading_name == 1) {
                name[name_bytesread] = '\0';
                reading_name = 0;
                name_bytesread = 0;
            } else if (reading_addr == 1) {
                addr[addr_bytesread] = '\0';
                reading_addr = 0;
                addr_bytesread = 0;
                // Insert a new node
                addHost(head, name, addr);
            } 
            continue;
        }
        
        if (newline) {
            reading_name = 1;
            newline = 0;
            name = (char*) malloc(200);
        }


        if (newline == 0 && reading_name == 0 && reading_addr == 0) {
            reading_addr = 1;
            addr = (char*) malloc(30);
        } 

        if (reading_name) {
            name_bytesread++;
            name[name_bytesread-1] = c;
        } 

        if (reading_addr) {
            addr_bytesread++;
            addr[addr_bytesread-1] = c;
        }
    }
    if (reading_addr == 1) {
                addr[addr_bytesread] = '\0';
                reading_addr = 0;
                addr_bytesread = 0;
                // Insert a new node
                addHost(head, name, addr);
                
    }
}


// Positions the file pointer to the position of the next line.  Returns NULL filepointer if EOF is reached
FILE* gotoNextLine(FILE* hosts) {
    char c = fgetc(hosts);
    while (c != '\n') {
        if (c == EOF)
            return NULL;
        c = fgetc(hosts);
    }
    return hosts;
}


int main(int argc, char** argv) {
    
    setbuf(stdout, NULL);
    signal(SIGSEGV, handler);   // install our handler
    
    /* Read the hosts file */
    FILE* hosts = fopen("hosts.txt", "r");
    HostNode* list = (HostNode*) malloc(sizeof(HostNode));
    list->name = NULL;
    fillList(list, hosts);
    printList(list);

    /* Open the socket and start listening */
    int udp_sock = open_udp_socket();
    sockaddr_in* myaddr = bind_udp_socket(udp_sock);
    sockaddr_in remaddr;     /* remote address */
    socklen_t addrlen = sizeof(remaddr);            /* length of addresses */
    int recvlen;                    /* # bytes received */
    unsigned char buf[BUFSIZE];     /* receive buffer */
    for (;;) {
        recvlen = recvfrom(udp_sock, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
        if (recvlen > 0) {
                buf[recvlen] = 0;
                parse_dns(buf, recvlen, udp_sock, (struct sockaddr *)&remaddr, list);
        }
    }

    fclose(hosts);
    close(udp_sock);

    return 0;
}