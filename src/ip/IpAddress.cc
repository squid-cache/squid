/*
 * DEBUG: section 14    IP Storage and Handling
 * AUTHOR: Amos Jeffries
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  This IpAddress code is copyright (C) 2007 by Treehouse Networks Ltd
 *  of New Zealand. It is published and Lisenced as an extension of
 *  squid under the same conditions as the main squid application.
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

#include "config.h"
#include "ip/IpAddress.h"
#include "ip/tools.h"
#include "util.h"


#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>  /* inet_ntoa() */
#endif


/* We want to use the debug routines when running as module of squid. */
/* otherwise fallback to printf if those are not available. */
#ifndef SQUID_DEBUG
#    define debugs(a,b,c)        //  drop.
#else
#warning "IpAddress built with Debugs!!"
#    include "../src/Debug.h"
#endif

/* Debugging only. Dump the address content when a fatal assert is encountered. */
#define IASSERT(a,b)  \
	if(!(b)){	printf("assert \"%s\" at line %d\n", a, __LINE__); \
		printf("IpAddress invalid? with IsIPv4()=%c, IsIPv6()=%c\n",(IsIPv4()?'T':'F'),(IsIPv6()?'T':'F')); \
		printf("ADDRESS:"); \
		for(unsigned int i = 0; i < sizeof(m_SocketAddr.sin6_addr); i++) { \
			printf(" %x", m_SocketAddr.sin6_addr.s6_addr[i]); \
		} printf("\n"); assert(b); \
	}

IpAddress::IpAddress()
{
    SetEmpty();
}

IpAddress::~IpAddress()
{
    memset(this,0,sizeof(IpAddress));
}

int
IpAddress::GetCIDR() const
{
    uint8_t shift,byte;
    uint8_t bit,caught;
    int len = 0;
    const uint8_t *ptr= m_SocketAddr.sin6_addr.s6_addr;

    /* Let's scan all the bits from Most Significant to Least */
    /* Until we find an "0" bit. Then, we return */
    shift=0;

    /* return IPv4 CIDR for any Mapped address */
    /* Thus only check the mapped bit */

    if ( !IsIPv6() ) {
        shift = 12;
    }

    for (; shift<sizeof(m_SocketAddr.sin6_addr) ; shift++) {
        byte= *(ptr+shift);

        if (byte == 0xFF) {
            len += 8;
            continue ;  /* A short-cut */
        }

        for (caught = 0 , bit= 7 ; !caught && (bit <= 7); bit--) {
            caught = ((byte & 0x80) == 0x00);  /* Found a '0' at 'bit' ? */

            if (!caught)
                len++;

            byte <<= 1;
        }

        if (caught)
            break; /* We have found the most significant "0" bit.  */
    }

    return len;
}

const int IpAddress::ApplyMask(IpAddress const &mask_addr)
{
    uint32_t *p1 = (uint32_t*)(&m_SocketAddr.sin6_addr);
    uint32_t const *p2 = (uint32_t const *)(&mask_addr.m_SocketAddr.sin6_addr);
    unsigned int blen = sizeof(m_SocketAddr.sin6_addr)/sizeof(uint32_t);
    unsigned int changes = 0;

    for (unsigned int i = 0; i < blen; i++) {
        if ((p1[i] & p2[i]) != p1[i])
            changes++;

        p1[i] &= p2[i];
    }

    return changes;
}

bool IpAddress::ApplyMask(const unsigned int cidr, int mtype)
{
    uint8_t clearbits = 0;
    uint8_t* p = NULL;

    // validation and short-cuts.
    if (cidr > 128)
        return false;

    if (cidr > 32 && mtype == AF_INET)
        return false;

    if (cidr == 0) {
        /* CIDR /0 is NoAddr regardless of the IPv4/IPv6 protocol */
        SetNoAddr();
        return true;
    }

    clearbits = (uint8_t)( (mtype==AF_INET6?128:32) -cidr);

    // short-cut
    if (clearbits == 0)
        return true;

    p = (uint8_t*)(&m_SocketAddr.sin6_addr) + 15;

    for (; clearbits>0 && p >= (uint8_t*)&m_SocketAddr.sin6_addr ; p-- ) {
        if (clearbits < 8) {
            *p &= ((0xFF << clearbits) & 0xFF);
            clearbits = 0;
        } else {
            *p &= 0x00;
            clearbits -= 8;
        }
    }

    return true;
}

bool IpAddress::IsSockAddr() const
{
    return (m_SocketAddr.sin6_port != 0);
}

bool IpAddress::IsIPv4() const
{
    return IsAnyAddr() || IsNoAddr() || IN6_IS_ADDR_V4MAPPED( &m_SocketAddr.sin6_addr );
}

bool IpAddress::IsIPv6() const
{
    return IsAnyAddr() || IsNoAddr() || !IN6_IS_ADDR_V4MAPPED( &m_SocketAddr.sin6_addr );
}

bool IpAddress::IsAnyAddr() const
{
    return IN6_IS_ADDR_UNSPECIFIED( &m_SocketAddr.sin6_addr );
}

/// NOTE: Does NOT clear the Port stored. Ony the Address and Type.
void IpAddress::SetAnyAddr()
{
    memset(&m_SocketAddr.sin6_addr, 0, sizeof(struct in6_addr) );
}

/// NOTE: completely empties the IpAddress structure. Address, Port, Type, everything.
void IpAddress::SetEmpty()
{
    memset(&m_SocketAddr, 0, sizeof(m_SocketAddr) );
}

const struct in6_addr IpAddress::v4_localhost = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01 }}
};
const struct in6_addr IpAddress::v4_anyaddr = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}
};
const struct in6_addr IpAddress::v4_noaddr = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}
};
const struct in6_addr IpAddress::v6_noaddr = {{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}
};


bool IpAddress::SetIPv4()
{
    if ( IsLocalhost() ) {
        m_SocketAddr.sin6_addr = v4_localhost;
        return true;
    }

    if ( IsAnyAddr() ) {
        m_SocketAddr.sin6_addr = v4_anyaddr;
        return true;
    }

    if ( IsIPv4())
        return true;

    // anything non-IPv4 and non-convertable is BAD.
    return false;
}

bool IpAddress::IsLocalhost() const
{
    return IN6_IS_ADDR_LOOPBACK( &m_SocketAddr.sin6_addr ) || IN6_ARE_ADDR_EQUAL( &m_SocketAddr.sin6_addr, &v4_localhost );
}

void IpAddress::SetLocalhost()
{
    if (Ip::EnableIpv6) {
        m_SocketAddr.sin6_addr = in6addr_loopback;
        m_SocketAddr.sin6_family = AF_INET6;
    } else {
        m_SocketAddr.sin6_addr = v4_localhost;
        m_SocketAddr.sin6_family = AF_INET;
    }
}

bool IpAddress::IsNoAddr() const
{
    // IFF the address == 0xff..ff (all ones)
    return IN6_ARE_ADDR_EQUAL( &m_SocketAddr.sin6_addr, &v6_noaddr );
}

void IpAddress::SetNoAddr()
{
    memset(&m_SocketAddr.sin6_addr, 0xFF, sizeof(struct in6_addr) );
    m_SocketAddr.sin6_family = AF_INET6;
}

bool IpAddress::GetReverseString6(char buf[MAX_IPSTRLEN], const struct in6_addr &dat) const
{
    char *p = buf;
    unsigned char const *r = dat.s6_addr;

    /* RFC1886 says: */
    /*     4321:0:1:2:3:4:567:89ab */
    /*     must be sent */
    /*     b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.int. */

    /* Work from the binary field. Anything else may have representation changes. */
    /* The sin6_port and sin6_addr members shall be in network byte order. */

    /* Compile Err: 'Too many arguments for format. */

    for (int i = 15; i >= 0; i--, p+=4) {
        snprintf(p, 5, "%x.%x.", ((r[i])&0xf), (((r[i])>>4)&0xf) );
    }

    /* RFC3152 says: */
    /*     ip6.int is now deprecated TLD, use ip6.arpa instead. */
    snprintf(p,10,"ip6.arpa.");

    return true;
}

bool IpAddress::GetReverseString4(char buf[MAX_IPSTRLEN], const struct in_addr &dat) const
{
    unsigned int i = (unsigned int) ntohl(dat.s_addr);
    snprintf(buf, 32, "%u.%u.%u.%u.in-addr.arpa.",
             i & 255,
             (i >> 8) & 255,
             (i >> 16) & 255,
             (i >> 24) & 255);
    return true;
}

bool IpAddress::GetReverseString(char buf[MAX_IPSTRLEN], int show_type) const
{

    if (show_type == AF_UNSPEC) {
        show_type = IsIPv6() ? AF_INET6 : AF_INET ;
    }

    if (show_type == AF_INET && IsIPv4()) {
        struct in_addr* tmp = (struct in_addr*)&m_SocketAddr.sin6_addr.s6_addr[12];
        return GetReverseString4(buf, *tmp);
    } else if ( show_type == AF_INET6 && IsIPv6() ) {
        return GetReverseString6(buf, m_SocketAddr.sin6_addr);
    }

    debugs(14,0, "Unable to convert '" << NtoA(buf,MAX_IPSTRLEN) << "' to the rDNS type requested.");

    buf[0] = '\0';

    return false;
}

IpAddress& IpAddress::operator =(const IpAddress &s)
{
    memcpy(this, &s, sizeof(IpAddress));
    return *this;
};

IpAddress::IpAddress(const char*s)
{
    SetEmpty();
    LookupHostIP(s, true);
}

bool IpAddress::operator =(const char* s)
{
    return LookupHostIP(s, true);
}

bool IpAddress::GetHostByName(const char* s)
{
    return LookupHostIP(s, false);
}

bool IpAddress::LookupHostIP(const char *s, bool nodns)
{
    int err = 0;

    short port = 0;

    struct addrinfo *res = NULL;

    struct addrinfo want;

    memset(&want, 0, sizeof(struct addrinfo));
    if (nodns) {
        want.ai_flags = AI_NUMERICHOST; // prevent actual DNS lookups!
    }
#if 0
    else if (!Ip::EnableIpv6)
        want.ai_family = AF_INET;  // maybe prevent IPv6 DNS lookups.
#endif

    if ( (err = xgetaddrinfo(s, NULL, &want, &res)) != 0) {
        debugs(14,3, HERE << "Given Non-IP '" << s << "': " << xgai_strerror(err) );
        /* free the memory xgetaddrinfo() dynamically allocated. */
        if (res) {
            xfreeaddrinfo(res);
            res = NULL;
        }
        return false;
    }

    /*
     *  NP: =(sockaddr_*) may alter the port. we don't want that.
     *      all we have been given as input was an IPA.
     */
    port = GetPort();
    operator=(*res);
    SetPort(port);

    /* free the memory xgetaddrinfo() dynamically allocated. */
    xfreeaddrinfo(res);

    res = NULL;

    return true;
}

IpAddress::IpAddress(struct sockaddr_in const &s)
{
    SetEmpty();
    operator=(s);
};

IpAddress& IpAddress::operator =(struct sockaddr_in const &s)
{
    Map4to6((const in_addr)s.sin_addr, m_SocketAddr.sin6_addr);
    m_SocketAddr.sin6_port = s.sin_port;
    m_SocketAddr.sin6_family = AF_INET6;
    return *this;
};

IpAddress& IpAddress::operator =(const struct sockaddr_storage &s)
{
    /* some AF_* magic to tell socket types apart and what we need to do */
    if (s.ss_family == AF_INET6) {
        memcpy(&m_SocketAddr, &s, sizeof(struct sockaddr_in));
    } else { // convert it to our storage mapping.
        struct sockaddr_in *sin = (struct sockaddr_in*)&s;
        m_SocketAddr.sin6_port = sin->sin_port;
        Map4to6( sin->sin_addr, m_SocketAddr.sin6_addr);
    }
    return *this;
};

IpAddress::IpAddress(struct sockaddr_in6 const &s)
{
    SetEmpty();
    operator=(s);
};

IpAddress& IpAddress::operator =(struct sockaddr_in6 const &s)
{
    memcpy(&m_SocketAddr, &s, sizeof(struct sockaddr_in6));

    return *this;
};

IpAddress::IpAddress(struct in_addr const &s)
{
    SetEmpty();
    operator=(s);
};

IpAddress& IpAddress::operator =(struct in_addr const &s)
{
    Map4to6((const in_addr)s, m_SocketAddr.sin6_addr);
    m_SocketAddr.sin6_family = AF_INET6;
    return *this;
};

IpAddress::IpAddress(struct in6_addr const &s)
{
    SetEmpty();
    operator=(s);
};

IpAddress& IpAddress::operator =(struct in6_addr const &s)
{

    memcpy(&m_SocketAddr.sin6_addr, &s, sizeof(struct in6_addr));
    m_SocketAddr.sin6_family = AF_INET6;

    return *this;
};

IpAddress::IpAddress(const IpAddress &s)
{
    SetEmpty();
    operator=(s);
}

IpAddress::IpAddress(IpAddress *s)
{
    SetEmpty();
    if (s)
        memcpy(this, s, sizeof(IpAddress));
}

IpAddress::IpAddress(const struct hostent &s)
{
    SetEmpty();
    operator=(s);
}

bool IpAddress::operator =(const struct hostent &s)
{

    struct in_addr* ipv4 = NULL;

    struct in6_addr* ipv6 = NULL;

    //struct hostent {
    //        char    *h_name;        /* official name of host */
    //        char    **h_aliases;    /* alias list */
    //        int     h_addrtype;     /* host address type */
    //        int     h_length;       /* length of address */
    //        char    **h_addr_list;  /* list of addresses */
    //}

    switch (s.h_addrtype) {

    case AF_INET:
        ipv4 = (in_addr*)(s.h_addr_list[0]);
        /* this */
        operator=(*ipv4);
        break;

    case AF_INET6:
        ipv6 = (in6_addr*)(s.h_addr_list[0]);
        /* this */
        operator=(*ipv6);
        break;

    default:
        IASSERT("false",false);
        return false;
    }

    return true;
}

IpAddress::IpAddress(const struct addrinfo &s)
{
    SetEmpty();
    operator=(s);
}

bool IpAddress::operator =(const struct addrinfo &s)
{

    struct sockaddr_in* ipv4 = NULL;

    struct sockaddr_in6* ipv6 = NULL;

    //struct addrinfo {
    //             int ai_flags;           /* input flags */
    //             int ai_family;          /* protocol family for socket */
    //             int ai_socktype;        /* socket type */
    //             int ai_protocol;        /* protocol for socket */
    //             socklen_t ai_addrlen;   /* length of socket-address */
    //             struct sockaddr *ai_addr; /* socket-address for socket */
    //             char *ai_canonname;     /* canonical name for service location */
    //             struct addrinfo *ai_next; /* pointer to next in list */
    //}

    switch (s.ai_family) {

    case AF_INET:
        ipv4 = (sockaddr_in*)(s.ai_addr);
        /* this */
        assert(ipv4);
        operator=(*ipv4);
        break;

    case AF_INET6:
        ipv6 = (sockaddr_in6*)(s.ai_addr);
        /* this */
        assert(ipv6);
        operator=(*ipv6);
        break;

    case AF_UNSPEC:
    default:
        // attempt to handle partially initialised addrinfo.
        // such as those where data only comes from getsockopt()
        if (s.ai_addr != NULL) {
            if (s.ai_addrlen == sizeof(struct sockaddr_in6)) {
                operator=(*((struct sockaddr_in6*)s.ai_addr));
                return true;
            } else if (s.ai_addrlen == sizeof(struct sockaddr_in)) {
                operator=(*((struct sockaddr_in*)s.ai_addr));
                return true;
            }
        }
        return false;
    }

    return true;
}

void IpAddress::GetAddrInfo(struct addrinfo *&dst, int force) const
{
    if (dst == NULL) {
        dst = new addrinfo;
    }

    memset(dst, 0, sizeof(struct addrinfo));

    // set defaults
    dst->ai_flags = AI_NUMERICHOST;

    if (dst->ai_socktype == 0)
        dst->ai_socktype = SOCK_STREAM;

    if (dst->ai_socktype == SOCK_STREAM // implies TCP
            && dst->ai_protocol == 0)
        dst->ai_protocol = IPPROTO_TCP;

    if (dst->ai_socktype == SOCK_DGRAM // implies UDP
            && dst->ai_protocol == 0)
        dst->ai_protocol = IPPROTO_UDP;

    if (force == AF_INET6 || (force == AF_UNSPEC && IsIPv6()) ) {
        dst->ai_addr = (struct sockaddr*)new sockaddr_in6;

        memset(dst->ai_addr,0,sizeof(struct sockaddr_in6));

        GetSockAddr(*((struct sockaddr_in6*)dst->ai_addr));

        dst->ai_addrlen = sizeof(struct sockaddr_in6);

        dst->ai_family = ((struct sockaddr_in6*)dst->ai_addr)->sin6_family;

#if 0
        /**
         * Enable only if you must and please report to squid-dev if you find a need for this.
         *
         * Vista may need this to cope with dual-stack (unsetting IP6_V6ONLY).
         *         http://msdn.microsoft.com/en-us/library/ms738574(VS.85).aspx
         * Linux appears to only do some things when its present.
         *         (93) Bad Protocol
         * FreeBSD dies horribly when using dual-stack with it set.
         *         (43) Protocol not supported
         */
        dst->ai_protocol = IPPROTO_IPV6;
#endif

    } else if ( force == AF_INET || (force == AF_UNSPEC && IsIPv4()) ) {

        dst->ai_addr = (struct sockaddr*)new sockaddr_in;

        memset(dst->ai_addr,0,sizeof(struct sockaddr_in));

        GetSockAddr(*((struct sockaddr_in*)dst->ai_addr));

        dst->ai_addrlen = sizeof(struct sockaddr_in);

        dst->ai_family = ((struct sockaddr_in*)dst->ai_addr)->sin_family;
    } else {
        IASSERT("false",false);
    }
}

void IpAddress::InitAddrInfo(struct addrinfo *&ai) const
{
    if (ai == NULL) {
        ai = new addrinfo;
        memset(ai,0,sizeof(struct addrinfo));
    }

    // remove any existing data.
    if (ai->ai_addr) delete ai->ai_addr;

    ai->ai_addr = (struct sockaddr*)new sockaddr_in6;
    memset(ai->ai_addr, 0, sizeof(struct sockaddr_in6));

    ai->ai_addrlen = sizeof(struct sockaddr_in6);

}

void IpAddress::FreeAddrInfo(struct addrinfo *&ai) const
{
    if (ai == NULL) return;

    if (ai->ai_addr) delete ai->ai_addr;

    ai->ai_addr = NULL;

    ai->ai_addrlen = 0;

    // NP: name fields are NOT allocated at present.
    delete ai;

    ai = NULL;
}

int IpAddress::matchIPAddr(const IpAddress &rhs) const
{
    uint8_t *l = (uint8_t*)m_SocketAddr.sin6_addr.s6_addr;
    uint8_t *r = (uint8_t*)rhs.m_SocketAddr.sin6_addr.s6_addr;

    // loop a byte-wise compare
    // NP: match MUST be R-to-L : L-to-R produces inconsistent gt/lt results at varying CIDR
    //     expected difference on CIDR is gt/eq or lt/eq ONLY.
    for (unsigned int i = 0 ; i < sizeof(m_SocketAddr.sin6_addr) ; i++) {

        if (l[i] < r[i])
            return -1;

        if (l[i] > r[i])
            return 1;
    }

    return 0;
}

bool IpAddress::operator ==(const IpAddress &s) const
{
    return (0 == matchIPAddr(s));
}

bool IpAddress::operator !=(const IpAddress &s) const
{
    return ! ( operator==(s) );
}

bool IpAddress::operator <=(const IpAddress &rhs) const
{
    if (IsAnyAddr() && !rhs.IsAnyAddr())
        return true;

    return (matchIPAddr(rhs) <= 0);
}

bool IpAddress::operator >=(const IpAddress &rhs) const
{
    if (IsNoAddr() && !rhs.IsNoAddr())
        return true;

    return ( matchIPAddr(rhs) >= 0);
}

bool IpAddress::operator >(const IpAddress &rhs) const
{
    if (IsNoAddr() && !rhs.IsNoAddr())
        return true;

    return ( matchIPAddr(rhs) > 0);
}

bool IpAddress::operator <(const IpAddress &rhs) const
{
    if (IsAnyAddr() && !rhs.IsAnyAddr())
        return true;

    return ( matchIPAddr(rhs) < 0);
}

unsigned short
IpAddress::GetPort() const
{
    return ntohs( m_SocketAddr.sin6_port );
}

unsigned short
IpAddress::SetPort(unsigned short prt)
{
    m_SocketAddr.sin6_port = htons(prt);

    return prt;
}

/**
 * NtoA Given a buffer writes a readable ascii version of the IPA and/or port stored
 *
 * Buffer must be of a size large enough to hold the converted address.
 * This size is provided in the form of a global defined variable MAX_IPSTRLEN
 * Should a buffer shorter be provided the string result will be truncated
 * at the length of the available buffer.
 *
 * A copy of the buffer is also returned for simple immediate display.
 */
char* IpAddress::NtoA(char* buf, const unsigned int blen, int force) const
{
    // Ensure we have a buffer.
    if (buf == NULL) {
        return NULL;
    }

    /* some external code may have blindly memset a parent. */
    /* thats okay, our default is known */
    if ( IsAnyAddr() ) {
        memcpy(buf,"::\0", min(static_cast<unsigned int>(3),blen));
        return buf;
    }

    memset(buf,0,blen); // clear buffer before write

    /* Pure-IPv6 CANNOT be displayed in IPv4 format. */
    /* However IPv4 CAN. */
    if ( force == AF_INET && !IsIPv4() ) {
        if ( IsIPv6() ) {
            memcpy(buf, "{!IPv4}\0", min(static_cast<unsigned int>(8),blen));
        }
        return buf;
    }

    if ( force == AF_INET6 || (force == AF_UNSPEC && IsIPv6()) ) {

        xinet_ntop(AF_INET6, &m_SocketAddr.sin6_addr, buf, blen);

    } else  if ( force == AF_INET || (force == AF_UNSPEC && IsIPv4()) ) {

        struct in_addr tmp;
        GetInAddr(tmp);
        xinet_ntop(AF_INET, &tmp, buf, blen);
    } else {
        debugs(14,0,"WARNING: Corrupt IP Address details OR required to display in unknown format (" <<
               force << "). accepted={" << AF_UNSPEC << "," << AF_INET << "," << AF_INET6 << "}");
        fprintf(stderr,"WARNING: Corrupt IP Address details OR required to display in unknown format (%d). accepted={%d,%d,%d} ",
                force, AF_UNSPEC, AF_INET, AF_INET6);
        memcpy(buf,"dead:beef::\0", min(static_cast<unsigned int>(13),blen));
        assert(false);
    }

    return buf;
}

unsigned int IpAddress::ToHostname(char *buf, const unsigned int blen) const
{
    char *p = buf;

    if (IsIPv6() && blen > 0) {
        *p = '[';
        p++;
    }

    /* 8 being space for [ ] : and port digits */
    if ( IsIPv6() )
        NtoA(p, blen-8, AF_INET6);
    else
        NtoA(p, blen-8, AF_INET);

    // find the end of the new string
    while (*p != '\0' && p < buf+blen)
        p++;

    if (IsIPv6() && p < (buf+blen-1) ) {
        *p = ']';
        p++;
    }

    /* terminate just in case. */
    *p = '\0';

    /* return size of buffer now used */
    return (p - buf);
}

char* IpAddress::ToURL(char* buf, unsigned int blen) const
{
    char *p = buf;

    // Ensure we have a buffer.

    if (buf == NULL) {
        return NULL;
    }

    p += ToHostname(p, blen);

    if (m_SocketAddr.sin6_port > 0 && p <= (buf+blen-7) ) {
        // ':port' (short int) needs at most 6 bytes plus 1 for 0-terminator
        snprintf(p, 7, ":%d", GetPort() );
    }

    // force a null-terminated string
    buf[blen-1] = '\0';

    return buf;
}

void IpAddress::GetSockAddr(struct sockaddr_storage &addr, const int family) const
{
    struct sockaddr_in *sin = NULL;

    if ( family == AF_INET && !IsIPv4()) {
        // FIXME INET6: caller using the wrong socket type!
        debugs(14, DBG_CRITICAL, HERE << "IpAddress::GetSockAddr : Cannot convert non-IPv4 to IPv4. from " << *this);
        assert(false);
    }

    if ( family == AF_INET6 || (family == AF_UNSPEC && IsIPv6()) ) {
        struct sockaddr_in6 *ss6 = (struct sockaddr_in6*)&addr;
        GetSockAddr(*ss6);
    } else if ( family == AF_INET || (family == AF_UNSPEC && IsIPv4()) ) {
        sin = (struct sockaddr_in*)&addr;
        GetSockAddr(*sin);
    } else {
        IASSERT("false",false);
    }
}

void IpAddress::GetSockAddr(struct sockaddr_in &buf) const
{
    if ( IsIPv4() ) {
        buf.sin_family = AF_INET;
        buf.sin_port = m_SocketAddr.sin6_port;
        Map6to4( m_SocketAddr.sin6_addr, buf.sin_addr);
    } else {
        debugs(14, DBG_CRITICAL, HERE << "IpAddress::GetSockAddr : Cannot convert non-IPv4 to IPv4. from " << *this );

        memset(&buf,0xFFFFFFFF,sizeof(struct sockaddr_in));
        assert(false);
    }

#if HAVE_SIN_LEN_IN_SAI
    /* not all OS have this field, BUT when they do it can be a problem if set wrong */
    buf.sin_len = sizeof(struct sockaddr_in);
#endif
}

void IpAddress::GetSockAddr(struct sockaddr_in6 &buf) const
{
    memcpy(&buf, &m_SocketAddr, sizeof(struct sockaddr_in6));
    /* maintain address family. It may have changed inside us. */
    buf.sin6_family = AF_INET6;

#if HAVE_SIN6_LEN_IN_SAI
    /* not all OS have this field, BUT when they do it can be a problem if set wrong */
    buf.sin6_len = sizeof(struct sockaddr_in6);
#endif
}

void IpAddress::Map4to6(const struct in_addr &in, struct in6_addr &out) const
{
    /* check for special cases */

    if ( in.s_addr == 0x00000000) {
        /* ANYADDR */
        out = v4_anyaddr;
    } else if ( in.s_addr == 0xFFFFFFFF) {
        /* NOADDR */
        out = v4_noaddr;
    } else {
        /* general */
        out = v4_anyaddr;
        out.s6_addr[12] = ((uint8_t *)&in.s_addr)[0];
        out.s6_addr[13] = ((uint8_t *)&in.s_addr)[1];
        out.s6_addr[14] = ((uint8_t *)&in.s_addr)[2];
        out.s6_addr[15] = ((uint8_t *)&in.s_addr)[3];
    }
}

void IpAddress::Map6to4(const struct in6_addr &in, struct in_addr &out) const
{
    /* ANYADDR */
    /* NOADDR */
    /* general */

    memset(&out, 0, sizeof(struct in_addr));
    ((uint8_t *)&out.s_addr)[0] = in.s6_addr[12];
    ((uint8_t *)&out.s_addr)[1] = in.s6_addr[13];
    ((uint8_t *)&out.s_addr)[2] = in.s6_addr[14];
    ((uint8_t *)&out.s_addr)[3] = in.s6_addr[15];
}

void IpAddress::GetInAddr(in6_addr &buf) const
{
    memcpy(&buf, &m_SocketAddr.sin6_addr, sizeof(struct in6_addr));
}

bool IpAddress::GetInAddr(struct in_addr &buf) const
{
    if ( IsIPv4() ) {
        Map6to4((const in6_addr)m_SocketAddr.sin6_addr, buf);
        return true;
    }

    // default:
    // non-compatible IPv6 Pure Address

    debugs(14,1, HERE << "IpAddress::GetInAddr : Cannot convert non-IPv4 to IPv4. IPA=" << *this);
    memset(&buf,0xFFFFFFFF,sizeof(struct in_addr));
    assert(false);
    return false;
}
