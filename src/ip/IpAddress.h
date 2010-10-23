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
#ifndef _INC_IPADDRESS_H
#define _INC_IPADDRESS_H

#include "getaddrinfo.h"
#include "getnameinfo.h"
#include "inet_ntop.h"
#include "inet_pton.h"


#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _SQUID_MSWIN_
#include <ws2tcpip.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)   /* protect NEXTSTEP */
#define _SQUID_NETDB_H_
#ifdef _SQUID_NEXT_
#include <netinet/in_systm.h>
#endif
#include <netdb.h>
#endif

#if HAVE_IOSFWD
#include <iosfwd>
#endif
#if HAVE_OSTREAM
#include <ostream>
#endif

/// Length of buffer that needs to be allocated to old a null-terminated IP-string
// Yuck. But there are still structures that need it to be an 'integer constant'.
#define MAX_IPSTRLEN  75

/**
 * Holds and manipulates IPv4, IPv6, and Socket Addresses.
 */
class IpAddress
{

public:
    /** @name Constructors and Destructor */
    /*@{*/
    IpAddress();
    IpAddress(const IpAddress &);

    /**
     * This constructor takes its own copy of the object pointed to for memory-safe usage later.
     * The caller must itself perform and ptr memory-management needed.
     *
     \deprecated Use of pointers can be nasty. Consider this a last-resort.
     *           Prefer the by-reference (&) version instead.
     */
    IpAddress(IpAddress *);
    IpAddress(const struct in_addr &);
    IpAddress(const struct sockaddr_in &);
    IpAddress(const struct in6_addr &);
    IpAddress(const struct sockaddr_in6 &);
    IpAddress(const struct hostent &);
    IpAddress(const struct addrinfo &);
    IpAddress(const char*);
    /// Default destructor.
    ~IpAddress();
    /*@}*/

    /** @name Assignment Operators */
    /*@{*/
    IpAddress& operator =(const IpAddress &s);
    IpAddress& operator =(struct sockaddr_in const &s);
    IpAddress& operator =(struct sockaddr_storage const &s);
    IpAddress& operator =(struct in_addr const &s);
    IpAddress& operator =(struct in6_addr const &s);
    IpAddress& operator =(struct sockaddr_in6 const &s);
    bool operator =(const struct hostent &s);
    bool operator =(const struct addrinfo &s);
    bool operator =(const char *s);
    /*@}*/

    /** @name Boolean Operators */
    /*@{*/
    bool operator ==(IpAddress const &s) const;
    bool operator !=(IpAddress const &s) const;
    bool operator >=(IpAddress const &rhs) const;
    bool operator <=(IpAddress const &rhs) const;
    bool operator >(IpAddress const &rhs) const;
    bool operator <(IpAddress const &rhs) const;

public:
    /* methods */

    /** Test whether content can be used as an IPv4 address
     \retval true  if content was received as an IPv4 address
     \retval true  if content was received as an IPv4-Mapped address
     \retval false if content was received as a non-mapped IPv6 native address.
     */
    bool IsIPv4() const;

    /** Test whether content can be used as an IPv6 address.
     \retval true  if --enable-ipv6 has been compiled.
     \retval false if --disable-ipv6 has been compiled.
     \retval false if --with-ipv6-split-stack has been compiled AND content is IPv4-mapped.
     */
    bool IsIPv6() const;

    /** Test whether content can be used as a Socket address.
     \retval true  if address AND port are both set
     \retval true  if content was received as a Socket address with port
     \retval false if port in unset (zero)
     */
    bool IsSockAddr() const;

    /** Content-neutral test for whether the specific IP case ANY_ADDR is stored.
     *  This is the default content of a new undefined IpAddress object.
     \retval true IPv4 0.0.0.0
     \retval true IPv6 ::
     \retval false anything else.
     */
    bool IsAnyAddr() const;

    /** Content-neutral test for whether the specific IP case NO_ADDR is stored.
     \retval true IPv4 255.255.255.255
     \retval true IPv6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
     \retval false anything else.
     */
    bool IsNoAddr() const;

    /** Content-neutral test for whether the specific IP case LOCALHOST is stored.
     *  This is the default content of a new undefined IpAddress object.
     \retval true IPv4 127.0.0.1
     \retval true IPv6 ::1
     \retval false anything else.
     */
    bool IsLocalhost() const;

    /*@}*/

    /** Retrieve the Port if stored.
     \retval 0 Port is unset or an error occured.
     \retval n Port associated with this address in host native -endian.
     */
    u_short GetPort() const;

    /** Set the Port value for an address.
     *  Replaces any previously existing Port value.
     \param port Port being assigned in host native -endian.
     \retval 0 Port is unset or an error occured.
     \retval n Port associated with this address in host native -endian.
     */
    u_short SetPort(u_short port);

    /// Set object to contain the specific IP case ANY_ADDR (format-neutral).
    /// see IsAnyAddr() for more detail.
    void SetAnyAddr();

    /// Set object to contain the specific IP case NO_ADDR (format-neutral).
    /// see IsNoAddr() for more detail.
    void SetNoAddr();

    /// Set object to contain the specific IP case LOCALHOST (format-neutral).
    /// see IsLocalhost() for more detail.
    void SetLocalhost();

    /// Fast reset of the stored content to what would be after default constructor.
    void SetEmpty();

    /** Require an IPv4-only address for this usage.
     *  Converts the object to prefer only IPv4 output.
     \retval true	Content can be IPv4
     \retval false	Content CANNOT be IPv4
     */
    bool SetIPv4();

    /**
     *  Valid results IF and only IF the stored IP address is actually a network bitmask
     \retval N number of bits which are set in the bitmask stored.
     */
    int GetCIDR() const;

    /** Apply a mask to the stored address.
     \param mask Netmask format to be bit-mask-AND'd over the stored address.
     */
    const int ApplyMask(const IpAddress &mask);

    /** Apply a mask to the stored address.
     *  CIDR will be converted appropriate to map the stored content.
     \param cidr   CIDR Mask being applied. As an integer in host format.
     \param mtype  Type of CIDR mask being applied (AF_INET or AF_INET6)
     */
    bool ApplyMask(const unsigned int cidr, int mtype);


    /** Return the ASCII equivalent of the address
     *  Semantically equivalent to the IPv4 inet_ntoa()
     *  eg. 127.0.0.1 (IPv4) or ::1 (IPv6)
     *  But for memory safety it requires a buffer as input
     *  instead of producing one magically.
     *  If buffer is not large enough the data is truncated silently.
     \param buf Allocated buffer to write address to
     \param len byte length of buffer available for writing.
     \param force (optional) require the IPA in a specific format.
     \return pointer to buffer received.
     */
    char* NtoA(char *buf, const unsigned int blen, int force = AF_UNSPEC) const;

    /** Return the ASCII equivalent of the address:port combination
     *  Provides a URL formatted version of the content.
     *  If buffer is not large enough the data is truncated silently.
     *  eg. 127.0.0.1:80 (IPv4) or [::1]:80 (IPv6)
     \param buf Allocated buffer to write address:port to
     \param len byte length of buffer available for writing.
     \return pointer to buffer received.
     */
    char* ToURL(char *buf, unsigned int len) const;

    /** Return a properly hostname formatted copy of the address
     *  Provides a URL formatted version of the content.
     *  If buffer is not large enough the data is truncated silently.
     *  eg. 127.0.0.1 (IPv4) or [::1] (IPv6)
     \param buf Allocated buffer to write address to
     \param len byte length of buffer available for writing.
     \return amount of buffer filled.
     */
    unsigned int ToHostname(char *buf, const unsigned int len) const;

    /**
     *  Convert the content into a Reverse-DNS string.
     *  The buffer sent MUST be allocated large enough to hold the resulting string.
     *  Name truncation will occur if buf does not have enough space.
     *  The constant MAX_IPSTRLEN is defined to provide for sizing arrays correctly.
     \param show_type  may be one of: AF_INET, AF_INET6 for the format of rDNS string wanted.
     *                 AF_UNSPEC the default displays the IP in its most advanced native form.
     \param buf        buffer to receive the text string output.
     */
    bool GetReverseString(char buf[MAX_IPSTRLEN], int show_type = AF_UNSPEC) const;

    /** Test how two IP relate to each other.
     \retval  0  IP are equal
     \retval  1  IP rhs is greater (numerically) than that stored.
     \retval -1  IP rhs is less (numerically) than that stored.
     */
    int matchIPAddr(const IpAddress &rhs) const;

    /**
     *  Get RFC 3493 addrinfo structure from the IpAddress data
     *  for protocol-neutral socket operations.
     *  Should be passed a NULL pointer of type struct addrinfo* it will
     *  allocate memory for the structures involved. (see FreeAddrInfo to clear).
     *  Defaults to a TCP streaming socket, if other values (such as UDP) are needed
     *  the caller MUST override these default settings.
     *  Some situations may also require an actual call to the system getaddrinfo()
     *  to pull relevant OS details for the socket.
     \par
     *  IpAddress allocated objects MUST be destructed by IpAddress::FreeAddrInfo
     *  System getaddrinfo() allocated objects MUST be freed with system freeaddrinfo()
     *
     \param ai structure to be filled out.
     \param force a specific sockaddr type is needed. default: don't care.
     */
    void GetAddrInfo(struct addrinfo *&ai, int force = AF_UNSPEC) const;

    /**
     *  Equivalent to the sysem call freeaddrinfo() but for IpAddress allocated data
     */
    void FreeAddrInfo(struct addrinfo *&ai) const;

    /**
     *  Initializes an empty addrinfo properly for use.
     *  It is intended for use in cases such as getsockopt() where the addrinfo is
     *  about to be changed and the stored details may not match the new ones coming.
     \param ai addrinfo struct to be initialized as AF_UNSPEC with large address buffer
     */
    void InitAddrInfo(struct addrinfo *&ai) const;

    /**
     *  Lookup a Host by Name. Equivalent to system call gethostbyname(char*)
     \param s The textual FQDN of the host being located.
     \retval true	lookup was successful and an IPA was located.
     \retval false	lookup failed or FQDN has no IP associated.
     */
    bool GetHostByName(const char *s);

public:
    /* FIXME: When C => C++ conversion is done will be fully private.
     * Legacy Transition Methods.
     * These are here solely to simplify the transition
     * when moving from converted code to unconverted
     * these functions can be used to convert this object
     * and pull out the data needed by the unconverted code
     * they are intentionaly hard to use, use GetAddrInfo() instead.
     * these functiosn WILL NOT be in the final public API after transition.
     */

    void GetSockAddr(struct sockaddr_storage &addr, const int family) const;

    /// \deprecated Deprecated for public use. Use IpAddress::GetAddrInfo()
    void GetSockAddr(struct sockaddr_in &) const;

    /// \deprecated Deprecated for public use. Use IpAddress::GetAddrInfo()
    bool GetInAddr(struct in_addr &) const; /* false if could not convert IPv6 down to IPv4 */
    void GetSockAddr(struct sockaddr_in6 &) const;

    /// \deprecated Deprecated for public use. Use IpAddress::GetAddrInfo()
    void GetInAddr(struct in6_addr &) const;

private:
    /* Conversion for dual-type internals */

    bool GetReverseString4(char buf[MAX_IPSTRLEN], const struct in_addr &dat) const;

    bool GetReverseString6(char buf[MAX_IPSTRLEN], const struct in6_addr &dat) const;

    void Map4to6(const struct in_addr &src, struct in6_addr &dest) const;

    void Map6to4(const struct in6_addr &src, struct in_addr &dest) const;

    // Worker behind GetHostName and char* converters
    bool LookupHostIP(const char *s, bool nodns);

    /* variables */
    struct sockaddr_in6 m_SocketAddr;

private:
    /* Internally used constants */
    static const unsigned int STRLEN_IP4A = 16;              // aaa.bbb.ccc.ddd\0
    static const unsigned int STRLEN_IP4R = 28;              // ddd.ccc.bbb.aaa.in-addr.arpa.\0
    static const unsigned int STRLEN_IP4S = 21;              // ddd.ccc.bbb.aaa:ppppp\0
    static const unsigned int MAX_IP4_STRLEN = STRLEN_IP4R;
    static const unsigned int STRLEN_IP6A = 42;           // [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/0
    static const unsigned int STRLEN_IP6R = 75;           // f.f.f.f f.f.f.f f.f.f.f f.f.f.f f.f.f.f f.f.f.f f.f.f.f f.f.f.f ipv6.arpa./0
    static const unsigned int STRLEN_IP6S = 48;           // [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:00000/0
    static const unsigned int MAX_IP6_STRLEN = STRLEN_IP6R;
    static const struct in6_addr v4_localhost;
    static const struct in6_addr v4_anyaddr;
    static const struct in6_addr v4_noaddr;
    static const struct in6_addr v6_noaddr;
};


inline std::ostream &
operator << (std::ostream &os, const IpAddress &ipa)
{
    char buf[MAX_IPSTRLEN];
    os << ipa.ToURL(buf,MAX_IPSTRLEN);
    return os;
}

// WAS _sockaddr_in_list in an earlier incarnation
class IpAddress_list
{
public:
    IpAddress_list() { next = NULL; };
    ~IpAddress_list() { if (next) delete next; next = NULL; };

    IpAddress s;
    IpAddress_list *next;
};


#endif /* _INC_IPADDRESS_H */
