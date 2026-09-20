/*
 * PSP netdb compatibility declarations.
 *
 * The legacy host lookup ABI is shared with PSPSDK libcglue.  The
 * protocol-independent address, service, and protocol lookup interfaces
 * are provided by newlib's PSP sysdir.
 */
#ifndef __NETDB_H__
#define __NETDB_H__

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETDB_INTERNAL   -1
#define NETDB_SUCCESS     0
#define HOST_NOT_FOUND    1
#define TRY_AGAIN         2
#define NO_RECOVERY       3
#define NO_DATA           4
#define NO_ADDRESS        NO_DATA

extern int h_errno;

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
    char *h_addr;
};

struct servent {
    char *s_name;
    char **s_aliases;
    int s_port;
    char *s_proto;
};

struct protoent {
    char *p_name;
    char **p_aliases;
    int p_proto;
};

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
};

#define EAI_ADDRFAMILY   1
#define EAI_AGAIN        2
#define EAI_BADFLAGS     3
#define EAI_FAIL         4
#define EAI_FAMILY       5
#define EAI_MEMORY       6
#define EAI_NONAME       7
#define EAI_OVERFLOW     8
#define EAI_SERVICE      9
#define EAI_SOCKTYPE    10
#define EAI_SYSTEM      11

#define AI_ADDRCONFIG   0x0001
#define AI_ALL          0x0002
#define AI_CANONNAME    0x0004
#define AI_NUMERICHOST  0x0008
#define AI_NUMERICSERV  0x0010
#define AI_PASSIVE      0x0020
#define AI_V4MAPPED     0x0040
#define AI_DEFAULT      (AI_V4MAPPED | AI_ADDRCONFIG)

#define NI_DGRAM        0x0001
#define NI_NAMEREQD     0x0002
#define NI_NOFQDN       0x0004
#define NI_NUMERICHOST  0x0008
#define NI_NUMERICSCOPE 0x0010
#define NI_NUMERICSERV  0x0020

#define NI_MAXHOST 1025
#define NI_MAXSERV 32

struct hostent *gethostbyaddr(const void *addr, int len, int type);
struct hostent *gethostbyname(const char *name);

struct servent *getservbyname(const char *name, const char *proto);
struct servent *getservbyport(int port, const char *proto);
struct protoent *getprotobyname(const char *name);
struct protoent *getprotobynumber(int proto);

int getaddrinfo(const char *nodename, const char *servname,
                const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *ai);
const char *gai_strerror(int ecode);
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *node, socklen_t nodelen,
                char *serv, socklen_t servlen, int flags);
const char *hstrerror(int err);

#ifdef __cplusplus
}
#endif

#endif
