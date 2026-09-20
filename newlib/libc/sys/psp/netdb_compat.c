/*
 * PSP protocol-independent network database compatibility.
 *
 * getaddrinfo/getnameinfo are based on the permissively licensed IPv4
 * compatibility implementation by Motoyuki Kasahara.  Service/protocol
 * lookup behavior is intentionally small and deterministic for PSP.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct service_record {
    const char *name;
    unsigned short port;
};

static const struct service_record services[] = {
    { "ftp", 21 },
    { "ssh", 22 },
    { "smtp", 25 },
    { "tftp", 69 },
    { "http", 80 },
    { "pop3", 110 },
    { "sftp", 115 },
    { "nntp", 119 },
    { "ntp", 123 },
    { "imap", 143 },
    { "snmp", 161 },
    { "irc", 194 },
    { "https", 443 },
    { "ldap", 389 },
    { "rsync", 873 },
    { "imaps", 993 },
    { "socks", 1080 }
};

static char *no_aliases[] = { NULL };
static struct servent service_result;
static struct protoent protocol_result;

static int proto_valid(const char *proto)
{
    return proto == NULL || strcmp(proto, "tcp") == 0 || strcmp(proto, "udp") == 0;
}

struct servent *getservbyname(const char *name, const char *proto)
{
    size_t i;

    if (name == NULL || !proto_valid(proto))
        return NULL;

    for (i = 0; i < sizeof(services) / sizeof(services[0]); ++i) {
        if (strcmp(name, services[i].name) == 0) {
            service_result.s_name = (char *)services[i].name;
            service_result.s_aliases = no_aliases;
            service_result.s_port = htons(services[i].port);
            service_result.s_proto = (char *)(proto != NULL ? proto : "tcp");
            return &service_result;
        }
    }

    return NULL;
}

struct servent *getservbyport(int port, const char *proto)
{
    size_t i;
    unsigned short host_port;

    if (!proto_valid(proto))
        return NULL;

    host_port = ntohs((unsigned short)port);
    for (i = 0; i < sizeof(services) / sizeof(services[0]); ++i) {
        if (services[i].port == host_port) {
            service_result.s_name = (char *)services[i].name;
            service_result.s_aliases = no_aliases;
            service_result.s_port = port;
            service_result.s_proto = (char *)(proto != NULL ? proto : "tcp");
            return &service_result;
        }
    }

    return NULL;
}

struct protoent *getprotobyname(const char *name)
{
    if (name == NULL)
        return NULL;

    if (strcmp(name, "tcp") == 0) {
        protocol_result.p_name = "tcp";
        protocol_result.p_aliases = no_aliases;
        protocol_result.p_proto = IPPROTO_TCP;
        return &protocol_result;
    }

    if (strcmp(name, "udp") == 0) {
        protocol_result.p_name = "udp";
        protocol_result.p_aliases = no_aliases;
        protocol_result.p_proto = IPPROTO_UDP;
        return &protocol_result;
    }

    return NULL;
}

struct protoent *getprotobynumber(int proto)
{
    if (proto == IPPROTO_TCP)
        return getprotobyname("tcp");
    if (proto == IPPROTO_UDP)
        return getprotobyname("udp");
    return NULL;
}

static int parse_decimal(const char *s, unsigned long *value)
{
    unsigned long v = 0;

    if (s == NULL || *s == '\0')
        return 0;

    while (*s != '\0') {
        if (*s < '0' || *s > '9')
            return 0;
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > 65535)
            return 0;
        ++s;
    }

    *value = v;
    return 1;
}

static int parse_ipv4(const char *s, struct in_addr *out)
{
    unsigned long octet[4];
    int i;

    if (s == NULL || out == NULL)
        return 0;

    for (i = 0; i < 4; ++i) {
        unsigned long v = 0;
        int digits = 0;

        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned long)(*s - '0');
            if (v > 255)
                return 0;
            ++s;
            ++digits;
        }

        if (digits == 0)
            return 0;
        octet[i] = v;

        if (i != 3) {
            if (*s != '.')
                return 0;
            ++s;
        }
    }

    if (*s != '\0')
        return 0;

    out->s_addr = htonl((octet[0] << 24) | (octet[1] << 16) |
                        (octet[2] << 8) | octet[3]);
    return 1;
}

static int format_ipv4(const struct in_addr *addr, char *dst, size_t len)
{
    unsigned long v;
    int n;

    if (addr == NULL || dst == NULL || len == 0)
        return 0;

    v = ntohl(addr->s_addr);
    n = snprintf(dst, len, "%lu.%lu.%lu.%lu",
                 (v >> 24) & 0xffUL, (v >> 16) & 0xffUL,
                 (v >> 8) & 0xffUL, v & 0xffUL);
    return n >= 0 && (size_t)n < len;
}

static int append_addrinfo(struct addrinfo **head, struct addrinfo **tail,
                           const struct in_addr *addr, unsigned short port,
                           const struct addrinfo *hints, const char *canon)
{
    struct addrinfo *ai;
    struct sockaddr_in *sa;

    ai = (struct addrinfo *)calloc(1, sizeof(*ai));
    sa = (struct sockaddr_in *)calloc(1, sizeof(*sa));
    if (ai == NULL || sa == NULL) {
        free(ai);
        free(sa);
        return EAI_MEMORY;
    }

    sa->sin_len = sizeof(*sa);
    sa->sin_family = AF_INET;
    sa->sin_port = port;
    sa->sin_addr = *addr;

    ai->ai_flags = hints != NULL ? hints->ai_flags : 0;
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints != NULL ? hints->ai_socktype : 0;
    ai->ai_protocol = hints != NULL ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(*sa);
    ai->ai_addr = (struct sockaddr *)sa;

    if (canon != NULL) {
        size_t n = strlen(canon) + 1;
        ai->ai_canonname = (char *)malloc(n);
        if (ai->ai_canonname == NULL) {
            free(sa);
            free(ai);
            return EAI_MEMORY;
        }
        memcpy(ai->ai_canonname, canon, n);
    }

    if (*tail != NULL)
        (*tail)->ai_next = ai;
    else
        *head = ai;
    *tail = ai;
    return 0;
}

void freeaddrinfo(struct addrinfo *ai)
{
    while (ai != NULL) {
        struct addrinfo *next = ai->ai_next;
        free(ai->ai_canonname);
        free(ai->ai_addr);
        free(ai);
        ai = next;
    }
}

int getaddrinfo(const char *nodename, const char *servname,
                const struct addrinfo *hints, struct addrinfo **res)
{
    struct addrinfo defaults;
    struct addrinfo *head = NULL;
    struct addrinfo *tail = NULL;
    struct in_addr numeric_addr;
    struct hostent *host = NULL;
    unsigned short port = 0;
    int rc;
    unsigned long numeric_port;

    if (res == NULL)
        return EAI_FAIL;
    *res = NULL;

    memset(&defaults, 0, sizeof(defaults));
    if (hints == NULL)
        hints = &defaults;

    if (nodename == NULL && servname == NULL)
        return EAI_NONAME;

    if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET)
        return EAI_FAMILY;

    if (hints->ai_socktype != 0 &&
        hints->ai_socktype != SOCK_STREAM &&
        hints->ai_socktype != SOCK_DGRAM)
        return EAI_SOCKTYPE;

    if (hints->ai_flags & ~(AI_ADDRCONFIG | AI_ALL | AI_CANONNAME |
                            AI_NUMERICHOST | AI_NUMERICSERV |
                            AI_PASSIVE | AI_V4MAPPED))
        return EAI_BADFLAGS;

    if (servname != NULL) {
        if (parse_decimal(servname, &numeric_port)) {
            port = htons((unsigned short)numeric_port);
        } else {
            const char *proto;
            struct servent *service;

            if (hints->ai_flags & AI_NUMERICSERV)
                return EAI_NONAME;

            proto = hints->ai_socktype == SOCK_DGRAM ? "udp" : "tcp";
            service = getservbyname(servname, proto);
            if (service == NULL)
                return EAI_SERVICE;
            port = (unsigned short)service->s_port;
        }
    }

    if (nodename == NULL) {
        numeric_addr.s_addr =
            htonl((hints->ai_flags & AI_PASSIVE) ? INADDR_ANY : INADDR_LOOPBACK);
        rc = append_addrinfo(&head, &tail, &numeric_addr, port, hints, NULL);
        if (rc != 0)
            return rc;
    } else if (parse_ipv4(nodename, &numeric_addr)) {
        rc = append_addrinfo(&head, &tail, &numeric_addr, port, hints,
                             (hints->ai_flags & AI_CANONNAME) ? nodename : NULL);
        if (rc != 0)
            return rc;
    } else {
        char **p;

        if (hints->ai_flags & AI_NUMERICHOST)
            return EAI_NONAME;

        host = gethostbyname(nodename);
        if (host == NULL) {
            if (h_errno == TRY_AGAIN)
                return EAI_AGAIN;
            if (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA)
                return EAI_NONAME;
            return EAI_FAIL;
        }

        for (p = host->h_addr_list; p != NULL && *p != NULL; ++p) {
            struct in_addr addr;
            const char *canon = NULL;

            if (host->h_length != (int)sizeof(addr))
                continue;

            memcpy(&addr, *p, sizeof(addr));
            if (head == NULL && (hints->ai_flags & AI_CANONNAME))
                canon = host->h_name;

            rc = append_addrinfo(&head, &tail, &addr, port, hints, canon);
            if (rc != 0) {
                freeaddrinfo(head);
                return rc;
            }
        }

        if (head == NULL)
            return EAI_NONAME;
    }

    *res = head;
    return 0;
}

static int copy_string(char *dst, socklen_t dstlen, const char *src)
{
    size_t len;

    if (dst == NULL)
        return 1;
    if (dstlen == 0)
        return 0;

    len = strlen(src);
    if (len >= (size_t)dstlen)
        return 0;

    memcpy(dst, src, len + 1);
    return 1;
}

int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *node, socklen_t nodelen,
                char *serv, socklen_t servlen, int flags)
{
    const struct sockaddr_in *sin;
    char hostbuf[NI_MAXHOST];
    char servbuf[NI_MAXSERV];

    if (sa == NULL || salen < sizeof(struct sockaddr_in))
        return EAI_FAMILY;
    if (sa->sa_family != AF_INET)
        return EAI_FAMILY;

    sin = (const struct sockaddr_in *)sa;

    if (node != NULL) {
        struct hostent *host = NULL;

        if (!(flags & NI_NUMERICHOST))
            host = gethostbyaddr(&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);

        if (host != NULL && host->h_name != NULL) {
            if (!copy_string(node, nodelen, host->h_name))
                return EAI_OVERFLOW;
        } else {
            if ((flags & NI_NAMEREQD) && !(flags & NI_NUMERICHOST))
                return EAI_NONAME;
            if (!format_ipv4(&sin->sin_addr, hostbuf, sizeof(hostbuf)))
                return EAI_FAIL;
            if (!copy_string(node, nodelen, hostbuf))
                return EAI_OVERFLOW;
        }
    }

    if (serv != NULL) {
        struct servent *service = NULL;

        if (!(flags & NI_NUMERICSERV))
            service = getservbyport(sin->sin_port,
                                    (flags & NI_DGRAM) ? "udp" : "tcp");

        if (service != NULL) {
            if (!copy_string(serv, servlen, service->s_name))
                return EAI_OVERFLOW;
        } else {
            int n = snprintf(servbuf, sizeof(servbuf), "%u",
                             (unsigned int)ntohs(sin->sin_port));
            if (n < 0 || (size_t)n >= sizeof(servbuf))
                return EAI_FAIL;
            if (!copy_string(serv, servlen, servbuf))
                return EAI_OVERFLOW;
        }
    }

    return 0;
}

const char *gai_strerror(int ecode)
{
    static const char *const messages[] = {
        "Success",
        "Address family for hostname not supported",
        "Temporary failure in name resolution",
        "Invalid value for ai_flags",
        "Non-recoverable failure in name resolution",
        "ai_family not supported",
        "Memory allocation failure",
        "Name or service not known",
        "Argument buffer overflow",
        "Service not supported for socket type",
        "Socket type not supported",
        "System error"
    };

    if (ecode < 0 || ecode > EAI_SYSTEM)
        return "Unknown error";
    return messages[ecode];
}

const char *hstrerror(int err)
{
    switch (err) {
    case NETDB_SUCCESS:
        return "Resolver error 0 (no error)";
    case HOST_NOT_FOUND:
        return "Unknown host";
    case TRY_AGAIN:
        return "Host name lookup failure";
    case NO_RECOVERY:
        return "Unknown server error";
    case NO_DATA:
        return "No address associated with name";
    default:
        return "Unknown resolver error";
    }
}
