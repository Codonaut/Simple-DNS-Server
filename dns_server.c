

#include "dns_server.h"

#define PORT 1153
#define BUFSIZE 2048

/*
*** TODO ***
* 1) Write parse_queries() function to handle the actual structure of a dns query(variable question name length)
*
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
    printf("after creation\n");
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


void parse_dns(char* msg, int recvlen) {
    dns_header* header = parse_header(msg);
    print_header(header);
    dns_question* query = parse_queries(msg, header->qu_count);
    msg = attach_answer(msg, header, query);
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

    for (pos=0; pos < 40; pos++) {
        //printf("char %d = %c\n", msg[pos], msg[pos]);
    }

    for (pos=qu_offset; qu_snagged < qu_count; pos++) {
        if (msg[pos] == 0) {

            qu_name = (char*) realloc(qu_name, sizeof(char) * (pos + 1));
            for (j=0; j<pos; j++)
                qu_name[j] = msg[qu_offset + j];
            qu_name_size = pos - qu_offset;
            qu_name[qu_name_size - 1] = '\0';

            (queries + qu_snagged)->qtype = msg[qu_offset + pos + 1] + msg[qu_offset + pos + 2];
            (queries + qu_snagged)->qclass = msg[qu_offset + pos + 3] + msg[qu_offset + pos + 4];
            (queries + qu_snagged)->qname = qu_name;

            qu_snagged++;   
        }
    }

    // Loop through the message until all queries are snagged
    /*for (pos=0; qu_snagged < qu_count; ) {
        //printf("Looking at char %d, pos=%d\n", msg[qu_offset + pos], pos);
        if (!isalpha(msg[qu_offset + pos]) && msg[qu_offset + pos] != 0) {
            // If the message byte is a number telling how many characters follow then
            // Add that number to the size, reallocate qu_name, and add those characters to qu_name

            //printf("Adding %d to qu_name_size\n", msg[qu_offset + pos]);
            seg_size = msg[qu_offset + pos];
            qu_name_size += seg_size;
            qu_name = (char *) realloc(qu_name, sizeof(char) * qu_name_size);
            
            // Add characters to qu_name
            for (j=pos + 1; j <= seg_size+pos; j++) {
                //printf("Writing char %d to %d\n", msg[qu_offset + j], last_write_index);
                qu_name[last_write_index] = msg[qu_offset + j];
                last_write_index ++;
            }

            //printf("qu_name_size = %d\n", qu_name_size);
            // Increment pos by size
            pos += msg[qu_offset + pos] + 1;
        } else {
            // A zero was encountered, and the query type and class are next
            
            (queries + qu_snagged)->qtype = msg[qu_offset + pos + 1] + msg[qu_offset + pos + 2];
            (queries + qu_snagged)->qclass = msg[qu_offset + pos + 3] + msg[qu_offset + pos + 4];

            // Increment the count of queries snagged, and increment the qu_offset
            qu_snagged++;
            qu_offset = pos + 5;
            pos = 0;
        }
    }*/
    //qu_name_size++;
    //qu_name = (char *) realloc(qu_name, sizeof(char) * qu_name_size);

    for (j=0; j<strlen(qu_name); j++)
        printf("char %d = %c\n", qu_name[j], qu_name[j]);

    printf("name: %s\n", qu_name);
    printf("name size: %d\n", qu_name_size);
    printf("qclass: %d\nqtype: %d\n", queries->qclass, queries->qtype);
}


void modify_headers(dns_header* header) {
    header->qr = 1;
    header->aa = 1;
    header->tc = 0;
    header->ra = 0;
    header->rcode = 0;
    header->an_count = htons(1);
}


char* attach_answer(char* msg, dns_header* header, dns_question* question) {
    modify_headers(header);
    int name_len = strlen(question->qname);
    int ans_len = name_len + 14;
    char* answer = (char *) malloc(sizeof(char) * ans_len);
    answer[0] = question->qname;
    answer[name_len] = htons(1);
    answer[name_len + 2] = htons(1);
    answer[name_len + 4] = htonl(86400);
    answer[name_len + 8] = htons(4);
    answer[name_len + 10] = htonl(5300);
    msg = (char *) realloc(msg, strlen(msg) + strlen(answer));
    msg += answer;
    return msg;
}


dns_header* parse_header(char* msg) {
    dns_header* header = (dns_header *) malloc(sizeof(dns_header));
    header->id = msg[0] + msg[1];
    header->rd = msg[2];
    header->rcode = msg[3];
    header->qu_count = msg[4] + msg[5];
    header->an_count = msg[6] + msg[7];
    header->authrr_count = msg[8] + msg[9];
    header->addrr_count = msg[10] + msg[11];
    /*header->id = msg[0] + msg[1];
    header->qr = (msg[2] & get_bitmask(7, 7)) >> 8;*/
    /*printf("bitmask: %d\n", get_bitmask(7,7));
    printf("QR: %d\n", header->qr);*/
    /*header->opcode = (msg[2] & get_bitmask(3,6)) >> 4;
    header->aa = (msg[2] & get_bitmask(2, 2)) >> 3;
    header->tc = (msg[2] & get_bitmask(1, 1)) >> 2;
    header->rd = (msg[2] & get_bitmask(0, 0)) >> 1;
    header->ra = (msg[3] & get_bitmask(7, 7)) >> 8;
    header->z = (msg[3] & get_bitmask(6, 6)) >> 7;
    header->ad = (msg[3] & get_bitmask(5, 5)) >> 6;
    header->cd = (msg[3] & get_bitmask(4, 4)) >> 5;
    header->rcode = (msg[3] & get_bitmask(0, 3)) >> 4;
    header->qu_count = msg[4] + msg[5];*/
    /*printf("qu_count: %d\n", header->qu_count);
    printf("rd: %d\n", header->rd);*/
    /*header->an_count = msg[6] + msg[7];
    header->authrr_count = msg[8] + msg[9];
    header->addrr_count = msg[10] + msg[11];*/
    /*printf("an_count: %d\n", header->an_count);
    printf("authrr_count: %d\n", header->authrr_count);*/
    return header;
}


int main(int argc, char** argv) {
    
    setbuf(stdout, NULL);
    signal(SIGSEGV, handler);   // install our handler
    
    int udp_sock = open_udp_socket();
    sockaddr_in* myaddr = bind_udp_socket(udp_sock);
    sockaddr_in remaddr;     /* remote address */
    socklen_t addrlen = sizeof(remaddr);            /* length of addresses */
    int recvlen;                    /* # bytes received */
    unsigned char buf[BUFSIZE];     /* receive buffer */
    printf("%d\n", get_bitmask(3,6));
    for (;;) {
        printf("waiting on port %d\n", PORT);
        recvlen = recvfrom(udp_sock, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
        printf("received %d bytes\n", recvlen);
        if (recvlen > 0) {
                buf[recvlen] = 0;
                printf("received message: \"%s\"\n", buf);
                parse_dns(buf, recvlen);
        }
    }
    
    return 0;
}
