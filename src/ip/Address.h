/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 14    IP Storage and Handling */

#ifndef _SQUID_SRC_IP_ADDRESS_H
#define _SQUID_SRC_IP_ADDRESS_H

#include "ip/forward.h"

#include <iosfwd>
#include <ostream>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#if HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

namespace Ip
{

/**
 * Holds and manipulates IPv4, IPv6, and Socket Addresses.
 */
class Address
{

public:
    /** @name Constructors and Destructor */
    /*@{*/
    Address() { setEmpty(); }
    Address(const struct in_addr &);
    Address(const struct sockaddr_in &);
    Address(const struct in6_addr &);
    Address(const struct sockaddr_in6 &);
    Address(const struct hostent &);
    Address(const struct addrinfo &);
    Address(const char*);
    ~Address() {}
    /*@}*/

    /** @name Assignment Operators */
    /*@{*/
    Address& operator =(struct sockaddr_in const &s);
    Address& operator =(struct sockaddr_storage const &s);
    Address& operator =(struct in_addr const &s);
    Address& operator =(struct in6_addr const &s);
    Address& operator =(struct sockaddr_in6 const &s);
    bool operator =(const struct hostent &s);
    bool operator =(const struct addrinfo &s);
    bool operator =(const char *s);
    /*@}*/

    /** @name Boolean Operators */
    /*@{*/
    bool operator ==(Address const &s) const;
    bool operator !=(Address const &s) const;
    bool operator >=(Address const &rhs) const;
    bool operator <=(Address const &rhs) const;
    bool operator >(Address const &rhs) const;
    bool operator <(Address const &rhs) const;

public:
    /* methods */

    /** Test whether content can be used as an IPv4 address
     \retval true  if content was received as an IPv4-Mapped address
     \retval false if content was received as a non-mapped IPv6 native address.
     */
    bool isIPv4() const;

    /** Test whether content can be used as an IPv6 address.
     \retval true  if content is a non IPv4-mapped address.
     \retval false if content is IPv4-mapped.
     */
    bool isIPv6() const;

    /** Test whether content can be used as a Socket address.
     \retval true  if address AND port are both set
     \retval true  if content was received as a Socket address with port
     \retval false if port in unset (zero)
     */
    bool isSockAddr() const;

    /** Content-neutral test for whether the specific IP case ANY_ADDR is stored.
     *  This is the default content of a new undefined Ip::Address object.
     \retval true IPv4 0.0.0.0
     \retval true IPv6 ::
     \retval false anything else.
     */
    bool isAnyAddr() const;

    /** Content-neutral test for whether the specific IP case NO_ADDR is stored.
     \retval true IPv4 255.255.255.255
     \retval true IPv6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
     \retval false anything else.
     */
    bool isNoAddr() const;

    /** Content-neutral test for whether the specific IP case LOCALHOST is stored.
     *  This is the default content of a new undefined Ip::Address object.
     \retval true IPv4 127.0.0.1
     \retval true IPv6 ::1
     \retval false anything else.
     */
    bool isLocalhost() const;

    /** Test whether content is an IPv6 Site-Local address.
     \retval true  if address begins with fd00::/8.
     \retval false if --disable-ipv6 has been compiled.
     \retval false if address does not match fd00::/8
     */
    bool isSiteLocal6() const;

    /** Test whether content is an IPv6 address with SLAAC EUI-64 embedded.
     \retval true  if address matches ::ff:fe00:0
     \retval false if --disable-ipv6 has been compiled.
     \retval false if address does not match ::ff:fe00:0
     */
    bool isSiteLocalAuto() const;

    /*@}*/

    /** Retrieve the Port if stored.
     \retval 0 Port is unset or an error occurred.
     \retval n Port associated with this address in host native -endian.
     */
    unsigned short port() const;

    /** Set the Port value for an address.
     *  Replaces any previously existing Port value.
     \param port Port being assigned in host native -endian.
     \retval 0 Port is unset or an error occurred.
     \retval n Port associated with this address in host native -endian.
     */
    unsigned short port(unsigned short port);

    /// Set object to contain the specific IP case ANY_ADDR (format-neutral).
    /// see isAnyAddr() for more detail.
    void setAnyAddr();

    /// Set object to contain the specific IP case NO_ADDR (format-neutral).
    /// see isNoAddr() for more detail.
    void setNoAddr();

    /// Set object to contain the specific IP case LOCALHOST (format-neutral).
    /// see isLocalhost() for more detail.
    void setLocalhost();

    /// Fast reset of the stored content to what would be after default constructor.
    void setEmpty();

    /** Require an IPv4-only address for this usage.
     *  Converts the object to prefer only IPv4 output.
     \retval true   Content can be IPv4
     \retval false  Content CANNOT be IPv4
     */
    bool setIPv4();

    /**
     *  Valid results IF and only IF the stored IP address is actually a network bitmask
     \retval N number of bits which are set in the bitmask stored.
     */
    int cidr() const;

    /** Apply a mask to the stored address.
     \param mask Netmask format to be bit-mask-AND'd over the stored address.
     */
    int applyMask(const Address &mask);

    /** Apply a mask to the stored address.
     *  CIDR will be converted appropriate to map the stored content.
     \param cidr   CIDR Mask being applied. As an integer in host format.
     \param mtype  Type of CIDR mask being applied (AF_INET or AF_INET6)
     */
    bool applyMask(const unsigned int cidr, int mtype);

    /// Apply so-called 'privacy masking' to IPv4 addresses,
    /// except localhost IP.
    /// IPv6 clients use 'privacy addressing' instead.
    void applyClientMask(const Address &mask);

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
    char* toStr(char *buf, const unsigned int blen, int force = AF_UNSPEC) const;

    /** Return the ASCII equivalent of the address:port combination
     *  Provides a URL formatted version of the content.
     *  If buffer is not large enough the data is truncated silently.
     *  eg. 127.0.0.1:80 (IPv4) or [::1]:80 (IPv6)
     \param buf Allocated buffer to write address:port to
     \param len byte length of buffer available for writing.
     \return pointer to buffer received.
     */
    char* toUrl(char *buf, unsigned int len) const;

    /** Return a properly hostname formatted copy of the address
     *  Provides a URL formatted version of the content.
     *  If buffer is not large enough the data is truncated silently.
     *  eg. 127.0.0.1 (IPv4) or [::1] (IPv6)
     \param buf Allocated buffer to write address to
     \param len byte length of buffer available for writing.
     \return amount of buffer filled.
     */
    unsigned int toHostStr(char *buf, const unsigned int len) const;

    /// Empties the address and then slowly imports the IP from a possibly
    /// [bracketed] portless host. For the semi-reverse operation, see
    /// toHostStr() which does export the port.
    /// \returns whether the conversion was successful
    bool fromHost(const char *hostWithoutPort);

    /**
     *  Convert the content into a Reverse-DNS string.
     *  The buffer sent MUST be allocated large enough to hold the resulting string.
     *  Name truncation will occur if buf does not have enough space.
     *  The constant MAX_IPSTRLEN is defined to provide for sizing arrays correctly.
     \param show_type  may be one of: AF_INET, AF_INET6 for the format of rDNS string wanted.
     *                 AF_UNSPEC the default displays the IP in its most advanced native form.
     \param buf        buffer to receive the text string output.
     */
    bool getReverseString(char buf[MAX_IPSTRLEN], int show_type = AF_UNSPEC) const;

    /** Test how two IP relate to each other.
     \retval  0  IP are equal
     \retval  1  IP rhs is greater (numerically) than that stored.
     \retval -1  IP rhs is less (numerically) than that stored.
     */
    int matchIPAddr(const Address &rhs) const;

    /** Compare taking IP, port, protocol, etc. into account. Returns an
        integer  less  than,  equal  to,  or greater than zero if the object
        is found, respectively, to be less than, to match, or to be greater
        than rhs. The exact ordering algorithm is not specified and may change.
    */
    int compareWhole(const Ip::Address &rhs) const;

    /**
     *  Get RFC 3493 addrinfo structure from the Ip::Address data
     *  for protocol-neutral socket operations.
     *  Should be passed a NULL pointer of type struct addrinfo* it will
     *  allocate memory for the structures involved. (see FreeAddr() to clear).
     *  Defaults to a TCP streaming socket, if other values (such as UDP) are needed
     *  the caller MUST override these default settings.
     *  Some situations may also require an actual call to the system getaddrinfo()
     *  to pull relevant OS details for the socket.
     \par
     *  Ip::Address allocated objects MUST be destructed by Ip::Address::FreeAddr
     *  System getaddrinfo() allocated objects MUST be freed with system freeaddrinfo()
     *
     \param ai structure to be filled out.
     \param force a specific sockaddr type is needed. default: don't care.
     */
    void getAddrInfo(struct addrinfo *&ai, int force = AF_UNSPEC) const;

    /**
     *  Equivalent to the sysem call freeaddrinfo() but for Ip::Address allocated data
     */
    static void FreeAddr(struct addrinfo *&ai);

    /**
     *  Initializes an empty addrinfo properly for use.
     *  It is intended for use in cases such as getsockopt() where the addrinfo is
     *  about to be changed and the stored details may not match the new ones coming.
     \param ai addrinfo struct to be initialized as AF_UNSPEC with large address buffer
     */
    static void InitAddr(struct addrinfo *&ai);

    /**
     *  Lookup a Host by Name. Equivalent to system call gethostbyname(char*)
     \param s The textual FQDN of the host being located.
     \retval true   lookup was successful and an IPA was located.
     \retval false  lookup failed or FQDN has no IP associated.
     */
    bool GetHostByName(const char *s);

public:
    /* FIXME: When C => C++ conversion is done will be fully private.
     * Legacy Transition Methods.
     * These are here solely to simplify the transition
     * when moving from converted code to unconverted
     * these functions can be used to convert this object
     * and pull out the data needed by the unconverted code
     * they are intentionaly hard to use, use getAddrInfo() instead.
     * these functions WILL NOT be in the final public API after transition.
     */

    void getSockAddr(struct sockaddr_storage &addr, const int family) const;
    void getSockAddr(struct sockaddr_in &) const;
    bool getInAddr(struct in_addr &) const; /* false if could not convert IPv6 down to IPv4 */
    void getSockAddr(struct sockaddr_in6 &) const;
    void getInAddr(struct in6_addr &) const;

private:
    /* Conversion for dual-type internals */

    bool getReverseString4(char buf[MAX_IPSTRLEN], const struct in_addr &dat) const;

    bool getReverseString6(char buf[MAX_IPSTRLEN], const struct in6_addr &dat) const;

    void map4to6(const struct in_addr &src, struct in6_addr &dest) const;

    void map6to4(const struct in6_addr &src, struct in_addr &dest) const;

    // Worker behind GetHostName and char* converters
    bool lookupHostIP(const char *s, bool nodns);

    /* variables */
    struct sockaddr_in6 mSocketAddr_;

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
operator << (std::ostream &os, const Address &ipa)
{
    char buf[MAX_IPSTRLEN];
    os << ipa.toUrl(buf,MAX_IPSTRLEN);
    return os;
}

// WAS _sockaddr_in_list in an earlier incarnation
class Address_list
{
public:
    Address_list() { next = NULL; };
    ~Address_list() { if (next) delete next; next = NULL; };

    Address s;
    Address_list *next;
};

} // namespace Ip

void parse_IpAddress_list_token(Ip::Address_list **, char *);

#endif /* _SQUID_SRC_IP_ADDRESS_H */

