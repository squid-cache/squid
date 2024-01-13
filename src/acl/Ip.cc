/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/Ip.h"
#include "acl/SplayInserter.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "wordlist.h"

#include <algorithm>

void *
ACLIP::operator new (size_t)
{
    fatal ("ACLIP::operator new: unused");
    return (void *)1;
}

void
ACLIP::operator delete (void *)
{
    fatal ("ACLIP::operator delete: unused");
}

/**
 * print/format an acl_ip_data structure for debugging output.
 *
 \param buf string buffer to write to
 \param len size of the buffer available
 */
void
acl_ip_data::toStr(char *buf, int len) const
{
    char *b1 = buf;
    char *b2 = nullptr;
    char *b3 = nullptr;
    int rlen = 0;

    addr1.toStr(b1, len - rlen );
    rlen = strlen(buf);
    b2 = buf + rlen;

    if (!addr2.isAnyAddr()) {
        b2[0] = '-';
        ++rlen;
        addr2.toStr(&(b2[1]), len - rlen );
        rlen = strlen(buf);
    } else
        b2[0] = '\0';

    b3 = buf + rlen;

    if (!mask.isNoAddr()) {
        b3[0] = '/';
        ++rlen;
        int cidr =  mask.cidr() - (addr1.isIPv4()?96:0);
        snprintf(&(b3[1]), (len-rlen), "%u", (unsigned int)(cidr<0?0:cidr) );
    } else
        b3[0] = '\0';
}

SBuf
acl_ip_data::toSBuf() const
{
    const int bufsz = MAX_IPSTRLEN*2+6;
    static char tmpbuf[ bufsz ];
    toStr(tmpbuf,bufsz);
    return SBuf(tmpbuf);
}

Ip::Address
acl_ip_data::firstAddress() const
{
    auto ip = addr1;
    if (!mask.isNoAddr())
        ip.applyMask(mask);
    return ip;
}

Ip::Address
acl_ip_data::lastAddress() const
{
    auto ip = addr2.isAnyAddr() ? addr1 : addr2;
    if (!mask.isNoAddr())
        ip.turnMaskedBitsOn(mask);
    return ip;
}

template <>
int
Acl::SplayInserter<acl_ip_data*>::Compare(const Value &a, const Value &b)
{
    if (a->lastAddress() < b->firstAddress())
        return -1; // the entire range a is to the left of range b

    if (a->firstAddress() > b->lastAddress())
        return +1; // the entire range a is to the right of range b

    return 0; // equal or partially overlapping ranges
}

template <>
bool
Acl::SplayInserter<acl_ip_data*>::IsSubset(const Value &a, const Value &b)
{
    return b->firstAddress() <= a->firstAddress() && a->lastAddress() <= b->lastAddress();
}

template <>
Acl::SplayInserter<acl_ip_data*>::Value
Acl::SplayInserter<acl_ip_data*>::MakeCombinedValue(const Value &a, const Value &b)
{
    const auto minLeft = std::min(a->firstAddress(), b->firstAddress());
    const auto maxRight = std::max(a->lastAddress(), b->lastAddress());
    return new acl_ip_data(minLeft, maxRight, Ip::Address::NoAddr(), nullptr);
}

/// reports acl_ip_data using squid.conf ACL value format
static std::ostream &
operator <<(std::ostream &os, acl_ip_data *value)
{
    if (value)
        os << value->toSBuf();
    return os;
}

/*
 * aclIpAddrNetworkCompare - The guts of the comparison for IP ACLs
 * matching checks.  The first argument (p) is a "host" address,
 * i.e.  the IP address of a cache client.  The second argument (q)
 * is an entry in some address-based access control element.  This
 * function is called via ACLIP::match() and the splay library.
 */
static int
aclIpAddrNetworkCompare(acl_ip_data * const &p, acl_ip_data * const &q)
{
    Ip::Address A = p->addr1;

    /* apply netmask */
    A.applyMask(q->mask);

    debugs(28,9, "aclIpAddrNetworkCompare: compare: " << p->addr1 << "/" << q->mask << " (" << A << ")  vs " <<
           q->addr1 << "-" << q->addr2 << "/" << q->mask);

    if (q->addr2.isAnyAddr()) {       /* single address check */

        return A.matchIPAddr( q->addr1 );

    } else {                   /* range address check */

        if ( (A >= q->addr1) && (A <= q->addr2) )
            return 0; /* valid. inside range. */
        else
            return A.matchIPAddr( q->addr1 ); /* outside of range, 'less than' */
    }
}

/**
 * Decode an ascii representation (asc) of a IP netmask address or CIDR,
 * and place resulting information in mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
bool
acl_ip_data::DecodeMask(const char *asc, Ip::Address &mask, int ctype)
{
    char junk;
    int a1 = 0;

    /* default is a mask that doesn't change any IP */
    mask.setNoAddr();

    if (!asc || !*asc) {
        return true;
    }

    /* An int mask 128, 32 */
    if ((sscanf(asc, "%d%c", &a1, &junk)==1) &&
            (a1 <= 128) && (a1  >= 0)
       ) {
        return mask.applyMask(a1, ctype);
    }

    /* dotted notation */
    /* assignment returns true if asc contained an IP address as text */
    if ((mask = asc)) {
        /* HACK: IPv4 netmasks don't cleanly map to IPv6 masks. */
        debugs(28, DBG_CRITICAL, "WARNING: Netmasks are deprecated. Please use CIDR masks instead.");
        if (mask.isIPv4()) {
            /* locate what CIDR mask was _probably_ meant to be in its native protocol format. */
            /* this will completely crap out with a security fail-open if the admin is playing mask tricks */
            /* however, that's their fault, and we do warn. see bug 2601 for the effects if we don't do this. */
            unsigned int m = mask.cidr();
            debugs(28, DBG_CRITICAL, "WARNING: IPv4 netmasks are particularly nasty when used to compare IPv6 to IPv4 ranges.");
            debugs(28, DBG_CRITICAL, "WARNING: For now we will assume you meant to write /" << m);
            /* reset the mask completely, and crop to the CIDR boundary back properly. */
            mask.setNoAddr();
            return mask.applyMask(m,AF_INET);
        }
        return true;
    }

    return false;
}

/* Handle either type of address, IPv6 will be discarded with a warning if disabled */
#define SCAN_ACL1_6       "%[0123456789ABCDEFabcdef:]-%[0123456789ABCDEFabcdef:]/%[0123456789]"
#define SCAN_ACL2_6       "%[0123456789ABCDEFabcdef:]-%[0123456789ABCDEFabcdef:]%c"
#define SCAN_ACL3_6       "%[0123456789ABCDEFabcdef:]/%[0123456789]"
#define SCAN_ACL4_6       "%[0123456789ABCDEFabcdef:]/%c"
/* We DO need to know which is which though, for proper CIDR masking. */
#define SCAN_ACL1_4       "%[0123456789.]-%[0123456789.]/%[0123456789.]"
#define SCAN_ACL2_4       "%[0123456789.]-%[0123456789.]%c"
#define SCAN_ACL3_4       "%[0123456789.]/%[0123456789.]"
#define SCAN_ACL4_4       "%[0123456789.]/%c"

acl_ip_data *
acl_ip_data::FactoryParse(const char *t)
{
    LOCAL_ARRAY(char, addr1, 256);
    LOCAL_ARRAY(char, addr2, 256);
    LOCAL_ARRAY(char, mask, 256);
    acl_ip_data *r = nullptr;
    acl_ip_data **Q = nullptr;
    Ip::Address temp;
    char c;
    unsigned int changed;
    acl_ip_data *q = new acl_ip_data;
    int iptype = AF_UNSPEC;

    debugs(28, 5, "aclIpParseIpData: " << t);

// IPv4
    if (sscanf(t, SCAN_ACL1_4, addr1, addr2, mask) == 3) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN1-v4: " << SCAN_ACL1_4);
        iptype=AF_INET;
    } else if (sscanf(t, SCAN_ACL2_4, addr1, addr2, &c) >= 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN2-v4: " << SCAN_ACL2_4);
        mask[0] = '\0';
        iptype=AF_INET;
    } else if (sscanf(t, SCAN_ACL3_4, addr1, mask) == 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN3-v4: " << SCAN_ACL3_4);
        addr2[0] = '\0';
        iptype=AF_INET;
    } else if (sscanf(t, SCAN_ACL4_4, addr1,&c) == 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN4-v4: " << SCAN_ACL4_4);
        addr2[0] = '\0';
        mask[0] = '\0';
        iptype=AF_INET;

// IPv6
    } else if (sscanf(t, SCAN_ACL1_6, addr1, addr2, mask) == 3) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN1-v6: " << SCAN_ACL1_6);
        iptype=AF_INET6;
    } else if (sscanf(t, SCAN_ACL2_6, addr1, addr2, &c) >= 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN2-v6: " << SCAN_ACL2_6);
        mask[0] = '\0';
        iptype=AF_INET6;
    } else if (sscanf(t, SCAN_ACL3_6, addr1, mask) == 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN3-v6: " << SCAN_ACL3_6);
        addr2[0] = '\0';
        iptype=AF_INET6;
    } else if (sscanf(t, SCAN_ACL4_6, addr1, mask) == 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: SCAN4-v6: " << SCAN_ACL4_6);
        addr2[0] = '\0';
        iptype=AF_INET6;

// Neither
    } else if (sscanf(t, "%[^/]/%s", addr1, mask) == 2) {
        debugs(28, 9, "aclIpParseIpData: '" << t << "' matched: non-IP pattern: %[^/]/%s");
        addr2[0] = '\0';
    } else if (sscanf(t, "%s", addr1) == 1) {
        /*
         * Note, must use plain getaddrinfo() here because at startup
         * ipcache hasn't been initialized
         * TODO: offload this to one of the Ip::Address lookups.
         */

        debugs(28, 5, "aclIpParseIpData: Lookup Host/IP " << addr1);
        struct addrinfo *hp = nullptr, *x = nullptr;
        struct addrinfo hints;
        Ip::Address *prev_addr = nullptr;

        memset(&hints, 0, sizeof(struct addrinfo));

        int errcode = getaddrinfo(addr1,nullptr,&hints,&hp);
        if (hp == nullptr) {
            delete q;
            if (strcmp(addr1, "::1") == 0) {
                debugs(28, DBG_IMPORTANT, "aclIpParseIpData: IPv6 has not been enabled in host DNS resolver.");
            } else {
                debugs(28, DBG_CRITICAL, "ERROR: aclIpParseIpData: Bad host/IP: '" << addr1 <<
                       "' in '" << t << "', flags=" << hints.ai_flags <<
                       " : (" << errcode << ") " << gai_strerror(errcode) );
                self_destruct();
            }
            return nullptr;
        }

        Q = &q;

        for (x = hp; x != nullptr;) {
            if ((r = *Q) == nullptr)
                r = *Q = new acl_ip_data;

            /* getaddrinfo given a host has a nasty tendency to return duplicate addr's */
            /* BUT sorted fortunately, so we can drop most of them easily */
            r->addr1 = *x;
            x = x->ai_next;
            if ( prev_addr && r->addr1 == *prev_addr) {
                debugs(28, 3, "aclIpParseIpData: Duplicate host/IP: '" << r->addr1 << "' dropped.");
                delete r;
                *Q = nullptr;
                continue;
            } else
                prev_addr = &r->addr1;

            debugs(28, 3, "aclIpParseIpData: Located host/IP: '" << r->addr1 << "'");

            r->addr2.setAnyAddr();
            r->mask.setNoAddr();

            Q = &r->next;

            debugs(28, 3, "" << addr1 << " --> " << r->addr1 );
        }

        freeaddrinfo(hp);

        if (*Q != nullptr) {
            debugs(28, DBG_CRITICAL, "ERROR: aclIpParseIpData: Bad host/IP: '" << t << "'");
            self_destruct();
            return nullptr;
        }

        return q;
    }

    /* ignore IPv6 addresses when built with IPv4-only */
    if ( iptype == AF_INET6 && !Ip::EnableIpv6) {
        debugs(28, DBG_IMPORTANT, "aclIpParseIpData: IPv6 has not been enabled.");
        delete q;
        return nullptr;
    }

    /* Decode addr1 */
    if (!*addr1 || !(q->addr1 = addr1)) {
        debugs(28, DBG_CRITICAL, "ERROR: aclIpParseIpData: unknown first address in '" << t << "'");
        delete q;
        self_destruct();
        return nullptr;
    }

    /* Decode addr2 */
    if (!*addr2)
        q->addr2.setAnyAddr();
    else if (!(q->addr2=addr2) ) {
        debugs(28, DBG_CRITICAL, "ERROR: aclIpParseIpData: unknown second address in '" << t << "'");
        delete q;
        self_destruct();
        return nullptr;
    }

    /* Decode mask (NULL or empty means a exact host mask) */
    if (!DecodeMask(mask, q->mask, iptype)) {
        debugs(28, DBG_CRITICAL, "ERROR: aclParseIpData: unknown netmask '" << mask << "' in '" << t << "'");
        delete q;
        self_destruct();
        return nullptr;
    }

    changed = 0;
    changed += q->addr1.applyMask(q->mask);
    changed += q->addr2.applyMask(q->mask);

    if (changed)
        debugs(28, DBG_CRITICAL, "WARNING: aclIpParseIpData: Netmask masks away part of the specified IP in '" << t << "'");

    // TODO: Either switch match() to Acl::SplayInserter<acl_ip_data*>::Compare()
    // range logic (that does not have these problems) OR warn that some (or
    // even all) addresses will never match this configured ACL value when
    // `q->addr1.applyMask()` above is positive:
    //
    // * A single configured IP value will never match:
    //   A.matchIPAddr(q->addr1) in aclIpAddrNetworkCompare() will not return 0.
    //   For example, `acl x src 127.0.0.1/24` does not match any address.
    //
    // * A configured IP range will not match any q->addr1/mask IPs:
    //   (A >= q->addr1) in aclIpAddrNetworkCompare() is false and
    //   A.matchIPAddr(q->addr1) will not return 0.
    //   For example, `acl y src 10.0.0.1-10.0.0.255/24` does not match 10.0.0.1.

    debugs(28,9, "Parsed: " << q->addr1 << "-" << q->addr2 << "/" << q->mask << "(/" << q->mask.cidr() <<")");

    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    /* Same as IPv6 (not so trivial to depict) */
    return q;
}

/// handles special ACL data parameters that apply to the whole ACLIP object
/// \returns true if input token is such a special parameter
bool
ACLIP::parseGlobal(const char * const token)
{
    // "all" matches entire Internet
    if (strcmp(token, "all") == 0) {
        debugs(28, 8, "found " << token);
        matchAnyIpv4 = true;
        matchAnyIpv6 = true;
        // TODO: Ignore all other ACL data parameters, with a once/ACL warning.
        return true;
    }

    // "ipv4" matches IPv4 Internet
    if (strcmp(token, "ipv4") == 0) {
        debugs(28, 8, "found " << token);
        matchAnyIpv4 = true;
        // TODO: Ignore all IPv4 data parameters, with a once/ACL warning.
        return true;
    }

    // "ipv4" matches IPv6 Internet
    if (strcmp(token, "ipv6") == 0) {
        debugs(28, 8, "found " << token);
        matchAnyIpv6 = true;
        // TODO: Ignore all IPv6 data parameters, with a once/ACL warning.
        return true;
    }

    /* Detect some old broken strings equivalent to 'all'.
     * treat them nicely. But be loud until its fixed.  */
    if (strcmp(token, "0/0") == 0 ||
            strcmp(token, "0.0.0.0/0") == 0 ||
            strcmp(token, "0.0.0.0/0.0.0.0") == 0 ||
            strcmp(token, "0.0.0.0-255.255.255.255") == 0 ||
            strcmp(token, "0.0.0.0-0.0.0.0/0") == 0) {

        debugs(28,DBG_CRITICAL, "ERROR: '" << token << "' needs to be replaced by the term 'all'.");
        debugs(28,DBG_CRITICAL, "SECURITY NOTICE: Overriding config setting. Using 'all' instead.");
        matchAnyIpv4 = true;
        matchAnyIpv6 = true;
        return true;
    }

    return false;
}

void
ACLIP::parse()
{
    if (data == nullptr)
        data = new IPSplay();

    while (char *t = ConfigParser::strtokFile()) {
        if (parseGlobal(t))
            continue;

        acl_ip_data *q = acl_ip_data::FactoryParse(t);

        while (q != nullptr) {
            /* pop each result off the list and add it to the data tree individually */
            acl_ip_data *next_node = q->next;
            q->next = nullptr;
            Acl::SplayInserter<acl_ip_data*>::Merge(*data, std::move(q));
            q = next_node;
        }
    }
}

ACLIP::~ACLIP()
{
    if (data) {
        data->destroy();
        delete data;
    }
}

struct IpAclDumpVisitor {
    SBufList contents;
    void operator() (acl_ip_data * const & ip) {
        contents.push_back(ip->toSBuf());
    }
};

SBufList
ACLIP::dump() const
{
    IpAclDumpVisitor visitor;

    if (matchAnyIpv4 && matchAnyIpv6)
        visitor.contents.push_back(SBuf("all"));
    else if (matchAnyIpv4)
        visitor.contents.push_back(SBuf("ipv4"));
    else if (matchAnyIpv6)
        visitor.contents.push_back(SBuf("ipv6"));

    data->visit(visitor);
    return visitor.contents;
}

bool
ACLIP::empty() const
{
    return data->empty() && !matchAnyIpv4 && !matchAnyIpv6;
}

int
ACLIP::match(const Ip::Address &clientip)
{
    if (matchAnyIpv4) {
        if (matchAnyIpv6) {
            debugs(28, 3, clientip << " found, matched 'all'");
            return true;
        }
        if (clientip.isIPv4()) {
            debugs(28, 3, clientip << " found, matched 'ipv4'");
            return true;
        }
        // fall through to look for an IPv6 match among IP parameters
    } else if (matchAnyIpv6) {
        if (clientip.isIPv6()) {
            debugs(28, 3, clientip << " found, matched 'ipv6'");
            return true;
        }
        // fall through to look for an IPv4 match among IP parameters
    }

    static acl_ip_data ClientAddress;
    /*
     * aclIpAddrNetworkCompare() takes two acl_ip_data pointers as
     * arguments, so we must create a fake one for the client's IP
     * address. Since we are scanning for a single IP mask and addr2
     * MUST be set to empty.
     */
    ClientAddress.addr1 = clientip;
    ClientAddress.addr2.setEmpty();
    ClientAddress.mask.setEmpty();

    const acl_ip_data * const * result =  data->find(&ClientAddress, aclIpAddrNetworkCompare);
    debugs(28, 3, "aclIpMatchIp: '" << clientip << "' " << (result ? "found" : "NOT found"));
    return (result != nullptr);
}

acl_ip_data::acl_ip_data() :addr1(), addr2(), mask(), next (nullptr) {}

acl_ip_data::acl_ip_data(Ip::Address const &anAddress1, Ip::Address const &anAddress2, Ip::Address const &aMask, acl_ip_data *aNext) : addr1(anAddress1), addr2(anAddress2), mask(aMask), next(aNext) {}

