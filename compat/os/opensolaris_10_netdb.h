/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Copied from OpenSolaris 10 public sources
 * http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/head/netdb.h
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*  Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*    All Rights Reserved   */

/*
 * BIND 4.9.3:
 *
 * Copyright (c) 1980, 1983, 1988, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * --Copyright--
 *
 * End BIND 4.9.3
 */

/*
 * Structures returned by network data base library.
 * All addresses are supplied in host order, and
 * returned in network order (suitable for use in system calls).
 */

#ifndef _NETDB_H
#define _NETDB_H

#include <sys/types.h>
#include <netinet/in.h>
#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
#include <sys/socket.h>
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */
#include <sys/feature_tests.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define _PATH_HEQUIV    "/etc/hosts.equiv"
#define _PATH_HOSTS "/etc/hosts"
#define _PATH_IPNODES   "/etc/inet/ipnodes"
#define _PATH_IPSECALGS "/etc/inet/ipsecalgs"
#define _PATH_NETMASKS  "/etc/netmasks"
#define _PATH_NETWORKS  "/etc/networks"
#define _PATH_PROTOCOLS "/etc/protocols"
#define _PATH_SERVICES  "/etc/services"

struct  hostent {
    char    *h_name;    /* official name of host */
    char    **h_aliases;    /* alias list */
    int h_addrtype; /* host address type */
    int h_length;   /* length of address */
    char    **h_addr_list;  /* list of addresses from name server */
#define h_addr  h_addr_list[0]  /* address, for backward compatiblity */
};

/*
 * addrinfo introduced with IPv6 for Protocol-Independent Hostname
 * and Service Name Translation.
 */

#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
struct addrinfo {
    int ai_flags;       /* AI_PASSIVE, AI_CANONNAME, ... */
    int ai_family;      /* PF_xxx */
    int ai_socktype;    /* SOCK_xxx */
    int ai_protocol;    /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
#ifdef __sparcv9
    int _ai_pad;        /* for backwards compat with old size_t */
#endif /* __sparcv9 */
    socklen_t ai_addrlen;
    char *ai_canonname; /* canonical name for hostname */
    struct sockaddr *ai_addr;   /* binary address */
    struct addrinfo *ai_next;   /* next structure in linked list */
};

/* addrinfo flags */
#define AI_PASSIVE  0x0008  /* intended for bind() + listen() */
#define AI_CANONNAME    0x0010  /* return canonical version of host */
#define AI_NUMERICHOST  0x0020  /* use numeric node address string */
#define AI_NUMERICSERV  0x0040  /* servname is assumed numeric */

/* getipnodebyname() flags */
#define AI_V4MAPPED 0x0001  /* IPv4 mapped addresses if no IPv6 */
#define AI_ALL      0x0002  /* IPv6 and IPv4 mapped addresses */
#define AI_ADDRCONFIG   0x0004  /* AAAA or A records only if IPv6/IPv4 cnfg'd */

/*
 * These were defined in RFC 2553 but not SUSv3
 * or RFC 3493 which obsoleted 2553.
 */
#if !defined(_XPG6) || defined(__EXTENSIONS__)
#define AI_DEFAULT  (AI_V4MAPPED | AI_ADDRCONFIG)

/* addrinfo errors */
#define EAI_ADDRFAMILY  1   /* address family not supported */
#define EAI_NODATA  7   /* no address */
#endif /* !defined(_XPG6) || defined(__EXTENSIONS__) */
#define EAI_AGAIN   2   /* DNS temporary failure */
#define EAI_BADFLAGS    3   /* invalid ai_flags */
#define EAI_FAIL    4   /* DNS non-recoverable failure */
#define EAI_FAMILY  5   /* ai_family not supported */
#define EAI_MEMORY  6   /* memory allocation failure */
#define EAI_NONAME  8   /* host/servname not known */
#define EAI_SERVICE 9   /* servname not supported for ai_socktype */
#define EAI_SOCKTYPE    10  /* ai_socktype not supported */
#define EAI_SYSTEM  11  /* system error in errno */
#define EAI_OVERFLOW    12  /* argument buffer overflow */
#define EAI_PROTOCOL    13
#define EAI_MAX     14

/* getnameinfo flags */
#define NI_NOFQDN   0x0001
#define NI_NUMERICHOST  0x0002  /* return numeric form of address */
#define NI_NAMEREQD 0x0004  /* request DNS name */
#define NI_NUMERICSERV  0x0008
#define NI_DGRAM    0x0010

#if !defined(_XPG6) || defined(__EXTENSIONS__)
/* Not listed in any standards document */
#define NI_WITHSCOPEID  0x0020
#define NI_NUMERICSCOPE 0x0040

/* getnameinfo max sizes as defined in RFC 2553 obsoleted in RFC 3493 */
#define NI_MAXHOST  1025
#define NI_MAXSERV  32
#endif /* !defined(_XPG6) || defined(__EXTENSIONS__) */
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

/*
 * Scope delimit character
 */
#define SCOPE_DELIMITER '%'

/*
 * Algorithm entry for /etc/inet/ipsecalgs which defines IPsec protocols
 * and algorithms.
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
typedef struct ipsecalgent {
    char **a_names;     /* algorithm names */
    int a_proto_num;    /* protocol number */
    int a_alg_num;      /* algorithm number */
    char *a_mech_name;  /* encryption framework mechanism name */
    int *a_block_sizes; /* supported block sizes */
    int *a_key_sizes;   /* supported key sizes */
    int a_key_increment;    /* key size increment */
    int *a_mech_params; /* mechanism specific parameters */
    int a_alg_flags;    /* algorithm flags */
} ipsecalgent_t;

/* well-known IPsec protocol numbers */

#define IPSEC_PROTO_AH      2
#define IPSEC_PROTO_ESP     3
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Assumption here is that a network number
 * fits in 32 bits -- probably a poor one.
 */
struct  netent {
    char        *n_name;    /* official name of net */
    char        **n_aliases;    /* alias list */
    int     n_addrtype; /* net address type */
    in_addr_t   n_net;      /* network # */
};

struct  protoent {
    char    *p_name;    /* official protocol name */
    char    **p_aliases;    /* alias list */
    int p_proto;    /* protocol # */
};

struct  servent {
    char    *s_name;    /* official service name */
    char    **s_aliases;    /* alias list */
    int s_port;     /* port # */
    char    *s_proto;   /* protocol to use */
};

#ifdef  __STDC__
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
struct hostent  *gethostbyname_r
(const char *, struct hostent *, char *, int, int *h_errnop);
struct hostent  *gethostbyaddr_r
(const char *, int, int, struct hostent *, char *, int, int *h_errnop);
struct hostent  *getipnodebyname(const char *, int, int, int *);
struct hostent  *getipnodebyaddr(const void *, size_t, int, int *);
void        freehostent(struct hostent *);
struct hostent  *gethostent_r(struct hostent *, char *, int, int *h_errnop);

struct servent  *getservbyname_r
(const char *name, const char *, struct servent *, char *, int);
struct servent  *getservbyport_r
(int port, const char *, struct servent *, char *, int);
struct servent  *getservent_r(struct    servent *, char *, int);

struct netent   *getnetbyname_r
(const char *, struct netent *, char *, int);
struct netent   *getnetbyaddr_r(long, int, struct netent *, char *, int);
struct netent   *getnetent_r(struct netent *, char *, int);

struct protoent *getprotobyname_r
(const char *, struct protoent *, char *, int);
struct protoent *getprotobynumber_r
(int, struct protoent *, char *, int);
struct protoent *getprotoent_r(struct protoent *, char *, int);

int getnetgrent_r(char **, char **, char **, char *, int);
int innetgr(const char *, const char *, const char *, const char *);
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
struct hostent  *gethostbyname(const char *);
struct hostent  *gethostent(void);
struct netent   *getnetbyaddr(in_addr_t, int);
struct netent   *getnetbyname(const char *);
struct netent   *getnetent(void);
struct protoent *getprotobyname(const char *);
struct protoent *getprotobynumber(int);
struct protoent *getprotoent(void);
struct servent  *getservbyname(const char *, const char *);
struct servent  *getservbyport(int, const char *);
struct servent  *getservent(void);

/* gethostbyaddr() second argument is a size_t only in unix95/unix98 */
#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
struct hostent  *gethostbyaddr(const void *, socklen_t, int);
#else
struct hostent  *gethostbyaddr(const void *, size_t, int);
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
int endhostent(void);
int endnetent(void);
int endprotoent(void);
int endservent(void);
int sethostent(int);
int setnetent(int);
int setprotoent(int);
int setservent(int);
#else
void endhostent(void);
void endnetent(void);
void endprotoent(void);
void endservent(void);
void sethostent(int);
void setnetent(int);
void setprotoent(int);
void setservent(int);
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)

#ifdef  _XPG6
#ifdef  __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname getaddrinfo __xnet_getaddrinfo
#else   /* __PRAGMA_REDEFINE_EXTNAME */
#define getaddrinfo __xnet_getaddrinfo
#endif  /* __PRAGMA_REDEFINE_EXTNAME */
#endif  /* _XPG6 */

int     getaddrinfo(const char *_RESTRICT_KYWD1,
                    const char *_RESTRICT_KYWD2,
                    const struct addrinfo *_RESTRICT_KYWD3,
                    struct addrinfo **_RESTRICT_KYWD4);
void        freeaddrinfo(struct addrinfo *);
const char  *gai_strerror(int);
int     getnameinfo(const struct sockaddr *_RESTRICT_KYWD1,
                    socklen_t, char *_RESTRICT_KYWD2, socklen_t,
                    char *_RESTRICT_KYWD3, socklen_t, int);
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
int getnetgrent(char **, char **, char **);
int setnetgrent(const char *);
int endnetgrent(void);
int rcmd(char **, unsigned short,
         const char *, const char *, const char *, int *);
int rcmd_af(char **, unsigned short,
            const char *, const char *, const char *, int *, int);
int rresvport_af(int *, int);
int rresvport_addr(int *, struct sockaddr_storage *);
int rexec(char **, unsigned short,
          const char *, const char *, const char *, int *);
int rexec_af(char **, unsigned short,
             const char *, const char *, const char *, int *, int);
int rresvport(int *);
int ruserok(const char *, int, const char *, const char *);
/* BIND */
struct hostent  *gethostbyname2(const char *, int);
void        herror(const char *);
const char  *hstrerror(int);
/* End BIND */

/* IPsec algorithm prototype definitions */
struct ipsecalgent *getipsecalgbyname(const char *, int, int *);
struct ipsecalgent *getipsecalgbynum(int, int, int *);
int getipsecprotobyname(const char *doi_name);
char *getipsecprotobynum(int doi_domain);
void freeipsecalgent(struct ipsecalgent *ptr);
/* END IPsec algorithm prototype definitions */

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */
#else   /* __STDC__ */
struct hostent  *gethostbyname_r();
struct hostent  *gethostbyaddr_r();
struct hostent  *getipnodebyname();
struct hostent  *getipnodebyaddr();
void         freehostent();
struct hostent  *gethostent_r();
struct servent  *getservbyname_r();
struct servent  *getservbyport_r();
struct servent  *getservent_r();
struct netent   *getnetbyname_r();
struct netent   *getnetbyaddr_r();
struct netent   *getnetent_r();
struct protoent *getprotobyname_r();
struct protoent *getprotobynumber_r();
struct protoent *getprotoent_r();
int      getnetgrent_r();
int      innetgr();

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
struct hostent  *gethostbyname();
struct hostent  *gethostbyaddr();
struct hostent  *gethostent();
struct netent   *getnetbyname();
struct netent   *getnetbyaddr();
struct netent   *getnetent();
struct servent  *getservbyname();
struct servent  *getservbyport();
struct servent  *getservent();
struct protoent *getprotobyname();
struct protoent *getprotobynumber();
struct protoent *getprotoent();
int      getnetgrent();

int sethostent();
int endhostent();
int setnetent();
int endnetent();
int setservent();
int endservent();
int setprotoent();
int endprotoent();
int setnetgrent();
int endnetgrent();
int rcmd();
int rcmd_af();
int rexec();
int rexec_af();
int rresvport();
int rresvport_af();
int rresvport_addr();
int ruserok();
/* BIND */
struct hostent  *gethostbyname2();
void        herror();
char        *hstrerror();
/* IPv6 prototype definitons */
int     getaddrinfo();
void        freeaddrinfo();
const char  *gai_strerror();
int     getnameinfo();
/* END IPv6 prototype definitions */
/* End BIND */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
/* IPsec algorithm prototype definitions */
struct ipsecalgent *getalgbyname();
struct ipsecalgent *getalgbydoi();
int getdoidomainbyname();
const char *getdoidomainbynum();
void freealgent();
/* END IPsec algorithm prototype definitions */
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#endif  /* __STDC__ */

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (when using the resolver)
 */

extern  int h_errno;

#ifdef  _REENTRANT
#ifdef  __STDC__
extern int  *__h_errno(void);
#else
extern int  *__h_errno();
#endif  /* __STDC__ */

/* Only #define h_errno if there is no conflict with other use */
#ifdef  H_ERRNO_IS_FUNCTION
#define h_errno (*__h_errno())
#endif  /* NO_H_ERRNO_DEFINE */
#endif  /* _REENTRANT */

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (left in extern int h_errno).
 */
#define HOST_NOT_FOUND  1 /* Authoritive Answer Host not found */
#define TRY_AGAIN   2 /* Non-Authoritive Host not found, or SERVERFAIL */
#define NO_RECOVERY 3 /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */
#define NO_DATA     4 /* Valid name, no data record of requested type */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define NO_ADDRESS  NO_DATA     /* no address, look for MX record */

/* BIND */
#define NETDB_INTERNAL  -1  /* see errno */
#define NETDB_SUCCESS   0   /* no problem */
/* End BIND */

#define MAXHOSTNAMELEN  256

#define MAXALIASES  35
#define MAXADDRS    35
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef  __cplusplus
}
#endif

#endif  /* _NETDB_H */

