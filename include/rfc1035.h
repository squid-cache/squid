/*
 * $Id: rfc1035.h,v 1.18 2007/09/20 11:58:21 amosjeffries Exp $
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#ifndef SQUID_RFC1035_H
#define SQUID_RFC1035_H

#include "config.h"
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* rfc1035 - DNS */
#define RFC1035_MAXHOSTNAMESZ 256
typedef struct _rfc1035_rr rfc1035_rr;
struct _rfc1035_rr {
    char name[RFC1035_MAXHOSTNAMESZ];
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rdlength;
    char *rdata;
};
typedef struct _rfc1035_query rfc1035_query;
struct _rfc1035_query {
    char name[RFC1035_MAXHOSTNAMESZ];
    unsigned short qtype;
    unsigned short qclass;
};
typedef struct _rfc1035_message rfc1035_message;
struct _rfc1035_message {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
    rfc1035_query *query;
    rfc1035_rr *answer;
};

SQUIDCEXTERN ssize_t rfc1035BuildAQuery(const char *hostname,
    char *buf,
    size_t sz,
    unsigned short qid,
    rfc1035_query * query);
SQUIDCEXTERN ssize_t rfc1035BuildPTRQuery(const struct in_addr,
    char *buf,
    size_t sz,
    unsigned short qid,
    rfc1035_query * query);
SQUIDCEXTERN void rfc1035SetQueryID(char *, unsigned short qid);
SQUIDCEXTERN int rfc1035MessageUnpack(const char *buf,
    size_t sz,
    rfc1035_message ** answer);
SQUIDCEXTERN int rfc1035QueryCompare(const rfc1035_query *, const rfc1035_query *);
SQUIDCEXTERN void rfc1035MessageDestroy(rfc1035_message * message);
SQUIDCEXTERN int rfc1035_errno;
SQUIDCEXTERN const char *rfc1035_error_message;

#define RFC1035_TYPE_A 1
#define RFC1035_TYPE_CNAME 5
#define RFC1035_TYPE_PTR 12
#define RFC1035_CLASS_IN 1


    /* Child Library RFC3596 Depends on some otherwise internal functions */
SQUIDCEXTERN int rfc1035HeaderPack(char *buf,
    size_t sz,
    rfc1035_message * hdr);
SQUIDCEXTERN int rfc1035HeaderUnpack(const char *buf,
    size_t sz,
    unsigned int *off,
    rfc1035_message * h);
SQUIDCEXTERN int rfc1035QuestionPack(char *buf,
     size_t sz,
    const char *name,
    const unsigned short type,
    const unsigned short _class);

#endif /* SQUID_RFC1035_H */
