/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

#if !defined(RFC1035_MAXHOSTNAMESZ)
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
 * is responsible for the order and handling of the lookups.
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

