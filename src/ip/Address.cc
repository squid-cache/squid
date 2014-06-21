/*
 * DEBUG: section 14    IP Storage and Handling
 * AUTHOR: Amos Jeffries
 * COPYRIGHT: GPL version 2, (C)2007-2013 Treehouse Networks Ltd.
 */
#include "squid.h"
#include "compat/inet_ntop.h"
#include "compat/getaddrinfo.h"
#include "Debug.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "util.h"

#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_ARPA_INET_H
/* for inet_ntoa() */
#include <arpa/inet.h>
#endif
#if HAVE_WS2TCPIP_H
// Windows IPv6 definitions
#include <ws2tcpip.h>
#endif

// some OS (ie WIndows) define IN6_ADDR_EQUAL instead
#if !defined(IN6_ARE_ADDR_EQUAL) && _SQUID_WINDOWS_
#define IN6_ARE_ADDR_EQUAL IN6_ADDR_EQUAL
#endif

/* Debugging only. Dump the address content when a fatal assert is encountered. */
#define IASSERT(a,b)  \
	if(!(b)){	printf("assert \"%s\" at line %d\n", a, __LINE__); \
		printf("Ip::Address invalid? with isIPv4()=%c, isIPv6()=%c\n",(isIPv4()?'T':'F'),(isIPv6()?'T':'F')); \
		printf("ADDRESS:"); \
		for(unsigned int i = 0; i < sizeof(mSocketAddr_.sin6_addr); ++i) { \
			printf(" %x", mSocketAddr_.sin6_addr.s6_addr[i]); \
		} printf("\n"); assert(b); \
	}

int
Ip::Address::cidr() const
{
    uint8_t shift,ipbyte;
    uint8_t bit,caught;
    int len = 0;
    const uint8_t *ptr= mSocketAddr_.sin6_addr.s6_addr;

    /* Let's scan all the bits from Most Significant to Least */
    /* Until we find an "0" bit. Then, we return */
    shift=0;

    /* return IPv4 CIDR for any Mapped address */
    /* Thus only check the mapped bit */

    if ( !isIPv6() ) {
        shift = 12;
    }

    for (; shift<sizeof(mSocketAddr_.sin6_addr) ; ++shift) {
        ipbyte= *(ptr+shift);

        if (ipbyte == 0xFF) {
            len += 8;
            continue ;  /* A short-cut */
        }

        for (caught = 0 , bit= 7 ; !caught && (bit <= 7); --bit) {
            caught = ((ipbyte & 0x80) == 0x00);  /* Found a '0' at 'bit' ? */

            if (!caught)
                ++len;

            ipbyte <<= 1;
        }

        if (caught)
            break; /* We have found the most significant "0" bit.  */
    }

    return len;
}

int
Ip::Address::applyMask(Ip::Address const &mask_addr)
{
    uint32_t *p1 = (uint32_t*)(&mSocketAddr_.sin6_addr);
    uint32_t const *p2 = (uint32_t const *)(&mask_addr.mSocketAddr_.sin6_addr);
    unsigned int blen = sizeof(mSocketAddr_.sin6_addr)/sizeof(uint32_t);
    unsigned int changes = 0;

    for (unsigned int i = 0; i < blen; ++i) {
        if ((p1[i] & p2[i]) != p1[i])
            ++changes;

        p1[i] &= p2[i];
    }

    return changes;
}

bool
Ip::Address::applyMask(const unsigned int cidrMask, int mtype)
{
    uint8_t clearbits = 0;
    uint8_t* p = NULL;

    // validation and short-cuts.
    if (cidrMask > 128)
        return false;

    if (cidrMask > 32 && mtype == AF_INET)
        return false;

    if (cidrMask == 0) {
        /* CIDR /0 is NoAddr regardless of the IPv4/IPv6 protocol */
        setNoAddr();
        return true;
    }

    clearbits = (uint8_t)( (mtype==AF_INET6?128:32) - cidrMask);

    // short-cut
    if (clearbits == 0)
        return true;

    p = (uint8_t*)(&mSocketAddr_.sin6_addr) + 15;

    for (; clearbits>0 && p >= (uint8_t*)&mSocketAddr_.sin6_addr ; --p ) {
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

bool
Ip::Address::isSockAddr() const
{
    return (mSocketAddr_.sin6_port != 0);
}

bool
Ip::Address::isIPv4() const
{
    return IN6_IS_ADDR_V4MAPPED( &mSocketAddr_.sin6_addr );
}

bool
Ip::Address::isIPv6() const
{
    return !isIPv4();
}

bool
Ip::Address::isAnyAddr() const
{
    return IN6_IS_ADDR_UNSPECIFIED(&mSocketAddr_.sin6_addr) || IN6_ARE_ADDR_EQUAL(&mSocketAddr_.sin6_addr, &v4_anyaddr);
}

/// NOTE: Does NOT clear the Port stored. Ony the Address and Type.
void
Ip::Address::setAnyAddr()
{
    memset(&mSocketAddr_.sin6_addr, 0, sizeof(struct in6_addr) );
}

/// NOTE: completely empties the Ip::Address structure. Address, Port, Type, everything.
void
Ip::Address::setEmpty()
{
    memset(&mSocketAddr_, 0, sizeof(mSocketAddr_) );
}

#if _SQUID_AIX_
// Bug 2885 comment 78 explains.
// In short AIX has a different netinet/in.h union definition
const struct in6_addr Ip::Address::v4_localhost = {{{ 0x00000000, 0x00000000, 0x0000ffff, 0x7f000001 }}};
const struct in6_addr Ip::Address::v4_anyaddr = {{{ 0x00000000, 0x00000000, 0x0000ffff, 0x00000000 }}};
const struct in6_addr Ip::Address::v4_noaddr = {{{ 0x00000000, 0x00000000, 0x0000ffff, 0xffffffff }}};
const struct in6_addr Ip::Address::v6_noaddr = {{{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff }}};
#else
const struct in6_addr Ip::Address::v4_localhost = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01 }}
};
const struct in6_addr Ip::Address::v4_anyaddr = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}
};
const struct in6_addr Ip::Address::v4_noaddr = {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}
};
const struct in6_addr Ip::Address::v6_noaddr = {{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}
};
#endif

bool
Ip::Address::setIPv4()
{
    if ( isLocalhost() ) {
        mSocketAddr_.sin6_addr = v4_localhost;
        return true;
    }

    if ( isAnyAddr() ) {
        mSocketAddr_.sin6_addr = v4_anyaddr;
        return true;
    }

    if ( isNoAddr() ) {
        mSocketAddr_.sin6_addr = v4_noaddr;
        return true;
    }

    if ( isIPv4())
        return true;

    // anything non-IPv4 and non-convertable is BAD.
    return false;
}

bool
Ip::Address::isLocalhost() const
{
    return IN6_IS_ADDR_LOOPBACK( &mSocketAddr_.sin6_addr ) || IN6_ARE_ADDR_EQUAL( &mSocketAddr_.sin6_addr, &v4_localhost );
}

void
Ip::Address::setLocalhost()
{
    if (Ip::EnableIpv6) {
        mSocketAddr_.sin6_addr = in6addr_loopback;
        mSocketAddr_.sin6_family = AF_INET6;
    } else {
        mSocketAddr_.sin6_addr = v4_localhost;
        mSocketAddr_.sin6_family = AF_INET;
    }
}

bool
Ip::Address::isSiteLocal6() const
{
    // RFC 4193 the site-local allocated range is fc00::/7
    // with fd00::/8 as the only currently allocated range (so we test it first).
    // BUG: as of 2010-02 Linux and BSD define IN6_IS_ADDR_SITELOCAL() to check for fec::/10
    return mSocketAddr_.sin6_addr.s6_addr[0] == static_cast<uint8_t>(0xfd) ||
           mSocketAddr_.sin6_addr.s6_addr[0] == static_cast<uint8_t>(0xfc);
}

bool
Ip::Address::isSiteLocalAuto() const
{
    return mSocketAddr_.sin6_addr.s6_addr[11] == static_cast<uint8_t>(0xff) &&
           mSocketAddr_.sin6_addr.s6_addr[12] == static_cast<uint8_t>(0xfe);
}

bool
Ip::Address::isNoAddr() const
{
    // IFF the address == 0xff..ff (all ones)
    return IN6_ARE_ADDR_EQUAL( &mSocketAddr_.sin6_addr, &v6_noaddr )
           || IN6_ARE_ADDR_EQUAL( &mSocketAddr_.sin6_addr, &v4_noaddr );
}

void
Ip::Address::setNoAddr()
{
    memset(&mSocketAddr_.sin6_addr, 0xFF, sizeof(struct in6_addr) );
    mSocketAddr_.sin6_family = AF_INET6;
}

bool
Ip::Address::getReverseString6(char buf[MAX_IPSTRLEN], const struct in6_addr &dat) const
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

    for (int i = 15; i >= 0; --i, p+=4) {
        snprintf(p, 5, "%x.%x.", ((r[i])&0xf), (((r[i])>>4)&0xf) );
    }

    /* RFC3152 says: */
    /*     ip6.int is now deprecated TLD, use ip6.arpa instead. */
    snprintf(p,10,"ip6.arpa.");

    return true;
}

bool
Ip::Address::getReverseString4(char buf[MAX_IPSTRLEN], const struct in_addr &dat) const
{
    unsigned int i = (unsigned int) ntohl(dat.s_addr);
    snprintf(buf, 32, "%u.%u.%u.%u.in-addr.arpa.",
             i & 255,
             (i >> 8) & 255,
             (i >> 16) & 255,
             (i >> 24) & 255);
    return true;
}

bool
Ip::Address::getReverseString(char buf[MAX_IPSTRLEN], int show_type) const
{

    if (show_type == AF_UNSPEC) {
        show_type = isIPv6() ? AF_INET6 : AF_INET ;
    }

    if (show_type == AF_INET && isIPv4()) {
        struct in_addr* tmp = (struct in_addr*)&mSocketAddr_.sin6_addr.s6_addr[12];
        return getReverseString4(buf, *tmp);
    } else if ( show_type == AF_INET6 && isIPv6() ) {
        return getReverseString6(buf, mSocketAddr_.sin6_addr);
    }

    debugs(14, DBG_CRITICAL, "Unable to convert '" << toStr(buf,MAX_IPSTRLEN) << "' to the rDNS type requested.");

    buf[0] = '\0';

    return false;
}

Ip::Address&
Ip::Address::operator =(const Ip::Address &s)
{
    memcpy(this, &s, sizeof(Ip::Address));
    return *this;
};

Ip::Address::Address(const char*s)
{
    setEmpty();
    lookupHostIP(s, true);
}

bool
Ip::Address::operator =(const char* s)
{
    return lookupHostIP(s, true);
}

bool
Ip::Address::GetHostByName(const char* s)
{
    return lookupHostIP(s, false);
}

bool
Ip::Address::lookupHostIP(const char *s, bool nodns)
{
    struct addrinfo want;
    memset(&want, 0, sizeof(struct addrinfo));
    if (nodns) {
        want.ai_flags = AI_NUMERICHOST; // prevent actual DNS lookups!
    }

    int err = 0;
    struct addrinfo *res = NULL;
    if ( (err = getaddrinfo(s, NULL, &want, &res)) != 0) {
        debugs(14,3, HERE << "Given Non-IP '" << s << "': " << gai_strerror(err) );
        /* free the memory getaddrinfo() dynamically allocated. */
        if (res)
            freeaddrinfo(res);
        return false;
    }

    /*
     *  NP: =(sockaddr_*) may alter the port. we don't want that.
     *      all we have been given as input was an IPA.
     */
    short portSaved = port();
    operator=(*res);
    port(portSaved);

    /* free the memory getaddrinfo() dynamically allocated. */
    freeaddrinfo(res);
    return true;
}

Ip::Address::Address(struct sockaddr_in const &s)
{
    setEmpty();
    operator=(s);
};

Ip::Address &
Ip::Address::operator =(struct sockaddr_in const &s)
{
    map4to6((const in_addr)s.sin_addr, mSocketAddr_.sin6_addr);
    mSocketAddr_.sin6_port = s.sin_port;
    mSocketAddr_.sin6_family = AF_INET6;
    return *this;
};

Ip::Address &
Ip::Address::operator =(const struct sockaddr_storage &s)
{
    /* some AF_* magic to tell socket types apart and what we need to do */
    if (s.ss_family == AF_INET6) {
        memcpy(&mSocketAddr_, &s, sizeof(struct sockaddr_in6));
    } else { // convert it to our storage mapping.
        struct sockaddr_in *sin = (struct sockaddr_in*)&s;
        mSocketAddr_.sin6_port = sin->sin_port;
        map4to6( sin->sin_addr, mSocketAddr_.sin6_addr);
    }
    return *this;
};

Ip::Address::Address(struct sockaddr_in6 const &s)
{
    setEmpty();
    operator=(s);
};

Ip::Address &
Ip::Address::operator =(struct sockaddr_in6 const &s)
{
    memcpy(&mSocketAddr_, &s, sizeof(struct sockaddr_in6));

    return *this;
};

Ip::Address::Address(struct in_addr const &s)
{
    setEmpty();
    operator=(s);
};

Ip::Address &
Ip::Address::operator =(struct in_addr const &s)
{
    map4to6((const in_addr)s, mSocketAddr_.sin6_addr);
    mSocketAddr_.sin6_family = AF_INET6;
    return *this;
};

Ip::Address::Address(struct in6_addr const &s)
{
    setEmpty();
    operator=(s);
};

Ip::Address &
Ip::Address::operator =(struct in6_addr const &s)
{

    memcpy(&mSocketAddr_.sin6_addr, &s, sizeof(struct in6_addr));
    mSocketAddr_.sin6_family = AF_INET6;

    return *this;
};

Ip::Address::Address(const Ip::Address &s)
{
    setEmpty();
    operator=(s);
}

Ip::Address::Address(const struct hostent &s)
{
    setEmpty();
    operator=(s);
}

bool
Ip::Address::operator =(const struct hostent &s)
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

Ip::Address::Address(const struct addrinfo &s)
{
    setEmpty();
    operator=(s);
}

bool
Ip::Address::operator =(const struct addrinfo &s)
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

void
Ip::Address::getAddrInfo(struct addrinfo *&dst, int force) const
{
    if (dst == NULL) {
        dst = new addrinfo;
    }

    memset(dst, 0, sizeof(struct addrinfo));

    // set defaults
    // Mac OS X does not emit a flag indicating the output is numeric (IP address)
#if _SQUID_APPLE_
    dst->ai_flags = 0;
#else
    dst->ai_flags = AI_NUMERICHOST;
#endif

    if (dst->ai_socktype == 0)
        dst->ai_socktype = SOCK_STREAM;

    if (dst->ai_socktype == SOCK_STREAM // implies TCP
            && dst->ai_protocol == 0)
        dst->ai_protocol = IPPROTO_TCP;

    if (dst->ai_socktype == SOCK_DGRAM // implies UDP
            && dst->ai_protocol == 0)
        dst->ai_protocol = IPPROTO_UDP;

    if (force == AF_INET6 || (force == AF_UNSPEC && Ip::EnableIpv6 && isIPv6()) ) {
        dst->ai_addr = (struct sockaddr*)new sockaddr_in6;

        memset(dst->ai_addr,0,sizeof(struct sockaddr_in6));

        getSockAddr(*((struct sockaddr_in6*)dst->ai_addr));

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

    } else if ( force == AF_INET || (force == AF_UNSPEC && isIPv4()) ) {

        dst->ai_addr = (struct sockaddr*)new sockaddr_in;

        memset(dst->ai_addr,0,sizeof(struct sockaddr_in));

        getSockAddr(*((struct sockaddr_in*)dst->ai_addr));

        dst->ai_addrlen = sizeof(struct sockaddr_in);

        dst->ai_family = ((struct sockaddr_in*)dst->ai_addr)->sin_family;
    } else {
        IASSERT("false",false);
    }
}

void
Ip::Address::InitAddrInfo(struct addrinfo *&ai)
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

void
Ip::Address::FreeAddrInfo(struct addrinfo *&ai)
{
    if (ai == NULL) return;

    if (ai->ai_addr) delete ai->ai_addr;

    ai->ai_addr = NULL;

    ai->ai_addrlen = 0;

    // NP: name fields are NOT allocated at present.
    delete ai;

    ai = NULL;
}

int
Ip::Address::matchIPAddr(const Ip::Address &rhs) const
{
    uint8_t *l = (uint8_t*)mSocketAddr_.sin6_addr.s6_addr;
    uint8_t *r = (uint8_t*)rhs.mSocketAddr_.sin6_addr.s6_addr;

    // loop a byte-wise compare
    // NP: match MUST be R-to-L : L-to-R produces inconsistent gt/lt results at varying CIDR
    //     expected difference on CIDR is gt/eq or lt/eq ONLY.
    for (unsigned int i = 0 ; i < sizeof(mSocketAddr_.sin6_addr) ; ++i) {

        if (l[i] < r[i])
            return -1;

        if (l[i] > r[i])
            return 1;
    }

    return 0;
}

int
Ip::Address::compareWhole(const Ip::Address &rhs) const
{
    return memcmp(this, &rhs, sizeof(*this));
}

bool
Ip::Address::operator ==(const Ip::Address &s) const
{
    return (0 == matchIPAddr(s));
}

bool
Ip::Address::operator !=(const Ip::Address &s) const
{
    return ! ( operator==(s) );
}

bool
Ip::Address::operator <=(const Ip::Address &rhs) const
{
    if (isAnyAddr() && !rhs.isAnyAddr())
        return true;

    return (matchIPAddr(rhs) <= 0);
}

bool
Ip::Address::operator >=(const Ip::Address &rhs) const
{
    if (isNoAddr() && !rhs.isNoAddr())
        return true;

    return ( matchIPAddr(rhs) >= 0);
}

bool
Ip::Address::operator >(const Ip::Address &rhs) const
{
    if (isNoAddr() && !rhs.isNoAddr())
        return true;

    return ( matchIPAddr(rhs) > 0);
}

bool
Ip::Address::operator <(const Ip::Address &rhs) const
{
    if (isAnyAddr() && !rhs.isAnyAddr())
        return true;

    return ( matchIPAddr(rhs) < 0);
}

unsigned short
Ip::Address::port() const
{
    return ntohs( mSocketAddr_.sin6_port );
}

unsigned short
Ip::Address::port(unsigned short prt)
{
    mSocketAddr_.sin6_port = htons(prt);

    return prt;
}

/**
 * toStr Given a buffer writes a readable ascii version of the IPA and/or port stored
 *
 * Buffer must be of a size large enough to hold the converted address.
 * This size is provided in the form of a global defined variable MAX_IPSTRLEN
 * Should a buffer shorter be provided the string result will be truncated
 * at the length of the available buffer.
 *
 * A copy of the buffer is also returned for simple immediate display.
 */
char *
Ip::Address::toStr(char* buf, const unsigned int blen, int force) const
{
    // Ensure we have a buffer.
    if (buf == NULL) {
        return NULL;
    }

    /* some external code may have blindly memset a parent. */
    /* thats okay, our default is known */
    if ( isAnyAddr() ) {
        if (isIPv6())
            memcpy(buf,"::\0", min(static_cast<unsigned int>(3),blen));
        else if (isIPv4())
            memcpy(buf,"0.0.0.0\0", min(static_cast<unsigned int>(8),blen));
        return buf;
    }

    memset(buf,0,blen); // clear buffer before write

    /* Pure-IPv6 CANNOT be displayed in IPv4 format. */
    /* However IPv4 CAN. */
    if ( force == AF_INET && !isIPv4() ) {
        if ( isIPv6() ) {
            memcpy(buf, "{!IPv4}\0", min(static_cast<unsigned int>(8),blen));
        }
        return buf;
    }

    if ( force == AF_INET6 || (force == AF_UNSPEC && isIPv6()) ) {

        inet_ntop(AF_INET6, &mSocketAddr_.sin6_addr, buf, blen);

    } else  if ( force == AF_INET || (force == AF_UNSPEC && isIPv4()) ) {

        struct in_addr tmp;
        getInAddr(tmp);
        inet_ntop(AF_INET, &tmp, buf, blen);
    } else {
        debugs(14, DBG_CRITICAL, "WARNING: Corrupt IP Address details OR required to display in unknown format (" <<
               force << "). accepted={" << AF_UNSPEC << "," << AF_INET << "," << AF_INET6 << "}");
        fprintf(stderr,"WARNING: Corrupt IP Address details OR required to display in unknown format (%d). accepted={%d,%d,%d} ",
                force, AF_UNSPEC, AF_INET, AF_INET6);
        memcpy(buf,"dead:beef::\0", min(static_cast<unsigned int>(13),blen));
        assert(false);
    }

    return buf;
}

unsigned int
Ip::Address::toHostStr(char *buf, const unsigned int blen) const
{
    char *p = buf;

    if (isIPv6() && blen > 0) {
        *p = '[';
        ++p;
    }

    /* 8 being space for [ ] : and port digits */
    if ( isIPv6() )
        toStr(p, blen-8, AF_INET6);
    else
        toStr(p, blen-8, AF_INET);

    // find the end of the new string
    while (*p != '\0' && p < buf+blen)
        ++p;

    if (isIPv6() && p < (buf+blen-1) ) {
        *p = ']';
        ++p;
    }

    /* terminate just in case. */
    *p = '\0';

    /* return size of buffer now used */
    return (p - buf);
}

char *
Ip::Address::toUrl(char* buf, unsigned int blen) const
{
    char *p = buf;

    // Ensure we have a buffer.

    if (buf == NULL) {
        return NULL;
    }

    p += toHostStr(p, blen);

    if (mSocketAddr_.sin6_port > 0 && p <= (buf+blen-7) ) {
        // ':port' (short int) needs at most 6 bytes plus 1 for 0-terminator
        snprintf(p, 7, ":%d", port() );
    }

    // force a null-terminated string
    buf[blen-1] = '\0';

    return buf;
}

void
Ip::Address::getSockAddr(struct sockaddr_storage &addr, const int family) const
{
    struct sockaddr_in *sin = NULL;

    if ( family == AF_INET && !isIPv4()) {
        // FIXME INET6: caller using the wrong socket type!
        debugs(14, DBG_CRITICAL, HERE << "Ip::Address::getSockAddr : Cannot convert non-IPv4 to IPv4. from " << *this);
        assert(false);
    }

    if ( family == AF_INET6 || (family == AF_UNSPEC && isIPv6()) ) {
        struct sockaddr_in6 *ss6 = (struct sockaddr_in6*)&addr;
        getSockAddr(*ss6);
    } else if ( family == AF_INET || (family == AF_UNSPEC && isIPv4()) ) {
        sin = (struct sockaddr_in*)&addr;
        getSockAddr(*sin);
    } else {
        IASSERT("false",false);
    }
}

void
Ip::Address::getSockAddr(struct sockaddr_in &buf) const
{
    if ( isIPv4() ) {
        buf.sin_family = AF_INET;
        buf.sin_port = mSocketAddr_.sin6_port;
        map6to4( mSocketAddr_.sin6_addr, buf.sin_addr);
    } else {
        debugs(14, DBG_CRITICAL, HERE << "Ip::Address::getSockAddr : Cannot convert non-IPv4 to IPv4. from " << *this );

        memset(&buf,0xFFFFFFFF,sizeof(struct sockaddr_in));
        assert(false);
    }

#if HAVE_SIN_LEN_IN_SAI
    /* not all OS have this field, BUT when they do it can be a problem if set wrong */
    buf.sin_len = sizeof(struct sockaddr_in);
#endif
}

void
Ip::Address::getSockAddr(struct sockaddr_in6 &buf) const
{
    memcpy(&buf, &mSocketAddr_, sizeof(struct sockaddr_in6));
    /* maintain address family. It may have changed inside us. */
    buf.sin6_family = AF_INET6;

#if HAVE_SIN6_LEN_IN_SAI
    /* not all OS have this field, BUT when they do it can be a problem if set wrong */
    buf.sin6_len = sizeof(struct sockaddr_in6);
#endif
}

void
Ip::Address::map4to6(const struct in_addr &in, struct in6_addr &out) const
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

void
Ip::Address::map6to4(const struct in6_addr &in, struct in_addr &out) const
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

void
Ip::Address::getInAddr(struct in6_addr &buf) const
{
    memcpy(&buf, &mSocketAddr_.sin6_addr, sizeof(struct in6_addr));
}

bool
Ip::Address::getInAddr(struct in_addr &buf) const
{
    if ( isIPv4() ) {
        map6to4(mSocketAddr_.sin6_addr, buf);
        return true;
    }

    // default:
    // non-compatible IPv6 Pure Address

    debugs(14, DBG_IMPORTANT, HERE << "Ip::Address::getInAddr : Cannot convert non-IPv4 to IPv4. IPA=" << *this);
    memset(&buf,0xFFFFFFFF,sizeof(struct in_addr));
    assert(false);
    return false;
}
