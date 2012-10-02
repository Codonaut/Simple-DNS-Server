#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <execinfo.h>
#include <signal.h>
#include <ctype.h>


typedef struct sockaddr_in sockaddr_in;

/* 
	DNS structures
*/

/* dns header - see rfc1035 */
/* this is the main header of a DNS message */
/* it is followed by zero or more questions, answers, authorities, and additional sections */
/* the last four count fields tell you how many of each to expect */

typedef struct {
	unsigned short id;
	unsigned char rd:1;
	unsigned char tc:1;
	unsigned char aa:1;
	unsigned char opcode:4;
	unsigned char qr:1;
	unsigned char rcode:4;
	unsigned char cd:1;
	unsigned char ad:1;
	unsigned char z:1;
	unsigned char ra:1;
	unsigned short qu_count;
	unsigned short an_count;
	unsigned short authrr_count;
	unsigned short addrr_count;
} dns_header;

/* dns question section format. This is prepended with a name */
/* check the specs for the format of a name. Instead of components */
/* separated by dots, each component is prefixed with a byte containing */
/* the length of that component */

typedef struct {
	unsigned short qtype;
	unsigned short qclass;
	char* qname;
} dns_question;

/* DNS resource record format */
/* The answer, authority, and additional sections all share this format. */
/* It is prepended with a name and suffixed with additional data */

typedef struct __attribute__ ((__packed__)) {
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short data_len;
} dns_rrhdr;

void handler(int sig);
int open_udp_socket();
void paddr(unsigned char* a);
sockaddr_in* bind_udp_socket(int udp_sock);
int get_bitmask(int lobit, int hibit);
void parse_dns(char* msg, int recvlen);
dns_question* parse_queries(char* msg, int qu_count);
dns_header* parse_header(char* msg);
