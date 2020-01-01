/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "dns/rfc2671.h"
#include "dns/rfc3596.h"
#include "util.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef SQUID_RFC1035_H
#error RFC3596 Library depends on RFC1035
#endif

/*
 * Low level DNS protocol routines
 *
 * Provides RFC3596 functions to handle purely IPv6 DNS.
 * Adds AAAA and IPv6 PTR records.
 * Other IPv6 records are not mentioned by this RFC.
 *
 * IPv4 equivalents are taken care of by the RFC1035 library.
 * Where one protocol lookup must be followed by another, the caller
 * is resposible for the order and handling of the lookups.
 *
 * KNOWN BUGS:
 *
 * UDP replies with TC set should be retried via TCP
 */

/**
 * Builds a message buffer with a QUESTION to lookup records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Returns the size of the query
 */
ssize_t
rfc3596BuildHostQuery(const char *hostname, char *buf, size_t sz, unsigned short qid, rfc1035_query * query, int qtype, ssize_t edns_sz)
{
    static rfc1035_message h;
    size_t offset = 0;
    memset(&h, '\0', sizeof(h));
    h.id = qid;
    h.qr = 0;
    h.rd = 1;
    h.opcode = 0;               /* QUERY */
    h.qdcount = (unsigned int) 1;
    h.arcount = (edns_sz > 0 ? 1 : 0);
    offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
    offset += rfc1035QuestionPack(buf + offset,
                                  sz - offset,
                                  hostname,
                                  qtype,
                                  RFC1035_CLASS_IN);
    if (edns_sz > 0)
        offset += rfc2671RROptPack(buf + offset, sz - offset, edns_sz);

    if (query) {
        query->qtype = qtype;
        query->qclass = RFC1035_CLASS_IN;
        xstrncpy(query->name, hostname, sizeof(query->name));
    }

    assert(offset <= sz);
    return offset;
}

/**
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * \return the size of the query
 */
ssize_t
rfc3596BuildAQuery(const char *hostname, char *buf, size_t sz, unsigned short qid, rfc1035_query * query, ssize_t edns_sz)
{
    return rfc3596BuildHostQuery(hostname, buf, sz, qid, query, RFC1035_TYPE_A, edns_sz);
}

/**
 * Builds a message buffer with a QUESTION to lookup AAAA records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * \return the size of the query
 */
ssize_t
rfc3596BuildAAAAQuery(const char *hostname, char *buf, size_t sz, unsigned short qid, rfc1035_query * query, ssize_t edns_sz)
{
    return rfc3596BuildHostQuery(hostname, buf, sz, qid, query, RFC1035_TYPE_AAAA, edns_sz);
}

/**
 * Builds a message buffer with a QUESTION to lookup PTR records
 * for an address.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * \return the size of the query
 */
ssize_t
rfc3596BuildPTRQuery4(const struct in_addr addr, char *buf, size_t sz, unsigned short qid, rfc1035_query * query, ssize_t edns_sz)
{
    static char rev[RFC1035_MAXHOSTNAMESZ];
    unsigned int i;

    i = (unsigned int) ntohl(addr.s_addr);
    snprintf(rev, RFC1035_MAXHOSTNAMESZ, "%u.%u.%u.%u.in-addr.arpa.",
             i & 255,
             (i >> 8) & 255,
             (i >> 16) & 255,
             (i >> 24) & 255);

    return rfc3596BuildHostQuery(rev, buf, sz, qid, query, RFC1035_TYPE_PTR, edns_sz);
}

ssize_t
rfc3596BuildPTRQuery6(const struct in6_addr addr, char *buf, size_t sz, unsigned short qid, rfc1035_query * query, ssize_t edns_sz)
{
    static char rev[RFC1035_MAXHOSTNAMESZ];
    const uint8_t* r = addr.s6_addr;
    char* p = rev;
    int i; /* NP: MUST allow signed for loop termination. */

    /* work from the raw addr field. anything else may have representation changes. */
    /* The sin6_port and sin6_addr members shall be in network byte order. */
    for (i = 15; i >= 0; i--, p+=4) {
        snprintf(p, 5, "%1x.%1x.", ((r[i])&0xf), (r[i]>>4)&0xf );
    }

    snprintf(p,10,"ip6.arpa.");

    return rfc3596BuildHostQuery(rev, buf, sz, qid, query, RFC1035_TYPE_PTR, edns_sz);
}

#if DRIVER

/* driver needs the rfc1035 code _without_ the main() */
#  define main(a,b) rfc1035_main(a,b)
#  include "rfc1035.c"
#  undef main(a,b)

#include <sys/socket.h>

int
main(int argc, char *argv[])
{
#define PACKET_BUFSZ        1024
    char input[PACKET_BUFSZ];
    char buf[PACKET_BUFSZ];
    char rbuf[PACKET_BUFSZ];
    size_t sz = PACKET_BUFSZ;
    unsigned short sid, sidb;
    int s;
    int rl;
    ssize_t edns_max = -1;

    struct sockaddr* S;
    int var = 1;

    if ( argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s [-6|-4] ip port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argv[var][0] == '-') {
        if (argv[var][1] == '4')
            prefer = AF_INET;
        else if (argv[var][1] == '6')
            prefer = AF_INET6;
        else if (argv[var][1] == 'E')
            edns_max = atoi(argv[var++]);
        else {
            fprintf(stderr, "usage: %s [-6|-4] [-E packet-size] ip port\n", argv[0]);
            fprintf(stderr, "  EDNS packets my be up to %d\n", PACKET_BUFSZ);
            exit(EXIT_FAILURE);
        }

        var++;
    }

    s = socket(PF_INET, SOCK_DGRAM, 0);

    if (s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&S, '\0', sizeof(S));

    if (prefer == 6) {
        S = (struct sockaddr *) new sockaddr_in6;
        memset(S,0,sizeof(struct sockaddr_in6));

        ((struct sockaddr_in6 *)S)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)S)->sin6_port = htons(atoi(argv[var+1]));

        if ( ! inet_pton(AF_INET6, argv[var], &((struct sockaddr_in6 *)S)->sin6_addr.s_addr) ) {
            perror("listen address");
            exit(EXIT_FAILURE);
        }

        s = socket(PF_INET6, SOCK_DGRAM, 0);
    } else {
        S = (struct sockaddr *) new sockaddr_in;
        memset(S,0,sizeof(struct sockaddr_in));

        ((struct sockaddr_in *)S)->sin_family = AF_INET;
        ((struct sockaddr_in *)S)->sin_port = htons(atoi(argv[var+1]));

        if ( ! inet_pton(AF_INET, argv[var], &((struct sockaddr_in *)S)->sin_addr.s_addr) ) {
            perror("listen address");
            exit(EXIT_FAILURE);
        }
    }

    while (fgets(input, PACKET_BUFSZ, stdin))
    {

        struct in6_addr junk6;

        struct in_addr junk4;
        strtok(input, "\r\n");
        memset(buf, '\0', PACKET_BUFSZ);
        sz = PACKET_BUFSZ;

        if (inet_pton(AF_INET6, input, &junk6)) {
            sid = rfc1035BuildPTRQuery6(junk6, buf, &sz, edns_max);
            sidb=0;
        } else if (inet_pton(AF_INET, input, &junk4)) {
            sid = rfc1035BuildPTRQuery4(junk4, buf, &sz, edns_max);
            sidb=0;
        } else {
            sid = rfc1035BuildAAAAQuery(input, buf, &sz, edns_max);
            sidb = rfc1035BuildAQuery(input, buf, &sz, edns_max);
        }

        sendto(s, buf, sz, 0, S, sizeof(*S));

        do {
            fd_set R;

            struct timeval to;
            FD_ZERO(&R);
            FD_SET(s, &R);
            to.tv_sec = 10;
            to.tv_usec = 0;
            rl = select(s + 1, &R, NULL, NULL, &to);
        } while (0);

        if (rl < 1) {
            printf("TIMEOUT\n");
            continue;
        }

        memset(rbuf, '\0', PACKET_BUFSZ);
        rl = recv(s, rbuf, PACKET_BUFSZ, 0);
        {
            unsigned short rid = 0;
            int i;
            int n;
            rfc1035_rr *answers = NULL;
            n = rfc1035AnswersUnpack(rbuf,
                                     rl,
                                     &answers,
                                     &rid);

            if (n < 0) {
                printf("ERROR %d\n", -n);
            } else if (rid != sid && rid != sidb) {
                printf("ERROR, ID mismatch (%#hx, %#hx)\n", sid, rid);
                printf("ERROR, ID mismatch (%#hx, %#hx)\n", sidb, rid);
            } else {
                printf("%d answers\n", n);

                for (i = 0; i < n; i++) {
                    if (answers[i].type == RFC1035_TYPE_A) {

                        struct in_addr a;
                        char tmp[16];
                        memcpy(&a, answers[i].rdata, 4);
                        printf("A\t%d\t%s\n", answers[i].ttl, inet_ntop(AF_INET,&a,tmp,16));
                    } else if (answers[i].type == RFC1035_TYPE_AAAA) {

                        struct in6_addr a;
                        char tmp[INET6_ADDRSTRLEN];
                        memcpy(&a, answers[i].rdata, 16);
                        printf("AAAA\t%d\t%s\n", answers[i].ttl, inet_ntop(AF_INET6,&a,tmp,sizeof(tmp)));
                    } else if (answers[i].type == RFC1035_TYPE_PTR) {
                        char ptr[RFC1035_MAXHOSTNAMESZ];
                        strncpy(ptr, answers[i].rdata, answers[i].rdlength);
                        printf("PTR\t%d\t%s\n", answers[i].ttl, ptr);
                    } else if (answers[i].type == RFC1035_TYPE_CNAME) {
                        char ptr[RFC1035_MAXHOSTNAMESZ];
                        strncpy(ptr, answers[i].rdata, answers[i].rdlength);
                        printf("CNAME\t%d\t%s\n", answers[i].ttl, ptr);
                    } else {
                        fprintf(stderr, "can't print answer type %d\n",
                                (int) answers[i].type);
                    }
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

#endif

