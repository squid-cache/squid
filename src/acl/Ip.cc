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
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "wordlist.h"

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
    char *b2 = NULL;
    char *b3 = NULL;
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

/*
 * aclIpAddrNetworkCompare - The guts of the comparison for IP ACLs
 * matching checks.  The first argument (p) is a "host" address,
 * i.e.  the IP address of a cache client.  The second argument (q)
 * is an entry in some address-based access control element.  This
 * function is called via ACLIP::match() and the splay library.
 */
int
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

/*
 * acl_ip_data::NetworkCompare - Compare two acl_ip_data entries.  Strictly
 * used by the splay insertion routine.  It emits a warning if it
 * detects a "collision" or overlap that would confuse the splay
 * sorting algorithm.  Much like aclDomainCompare.
 * The first argument (p) is a "host" address, i.e. the IP address of a cache client.
 * The second argument (b) is a "network" address that might have a subnet and/or range.
 * We mask the host address bits with the network subnet mask.
 */
int
acl_ip_data::NetworkCompare(acl_ip_data * const & a, acl_ip_data * const &b)
{
    int ret;
    bool bina = true;
    ret = aclIpAddrNetworkCompare(b, a);

    if (ret != 0) {
        bina = false;
        ret = aclIpAddrNetworkCompare(a, b);
    }

    if (ret == 0) {
        char buf_n1[3*(MAX_IPSTRLEN+1)];
        char buf_n2[3*(MAX_IPSTRLEN+1)];
        if (bina) {
            b->toStr(buf_n1, 3*(MAX_IPSTRLEN+1));
            a->toStr(buf_n2, 3*(MAX_IPSTRLEN+1));
        } else {
            a->toStr(buf_n1, 3*(MAX_IPSTRLEN+1));
            b->toStr(buf_n2, 3*(MAX_IPSTRLEN+1));
        }
        debugs(28, DBG_CRITICAL, "WARNING: (" << (bina?'B':'A') << ") '" << buf_n1 << "' is a subnetwork of (" << (bina?'A':'B') << ") '" << buf_n2 << "'");
        debugs(28, DBG_CRITICAL, "WARNING: because of this '" << (bina?buf_n2:buf_n1) << "' is ignored to keep splay tree searching predictable");
        debugs(28, DBG_CRITICAL, "WARNING: You should probably remove '" << buf_n1 << "' from the ACL named '" << AclMatchedName << "'");
    }

    return ret;
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
            /* however, thats their fault, and we do warn. see bug 2601 for the effects if we don't do this. */
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
    acl_ip_data *r = NULL;
    acl_ip_data **Q = NULL;
    Ip::Address temp;
    char c;
    unsigned int changed;
    acl_ip_data *q = new acl_ip_data;
    int iptype = AF_UNSPEC;

    debugs(28, 5, "aclIpParseIpData: " << t);

    /* Special ACL RHS "all" matches entire Internet */
    if (strcmp(t, "all") == 0) {
        debugs(28, 9, "aclIpParseIpData: magic 'all' found.");
        q->addr1.setAnyAddr();
        q->addr2.setEmpty();
        q->mask.setAnyAddr();
        return q;
    }

    /* Detect some old broken strings equivalent to 'all'.
     * treat them nicely. But be loud until its fixed.  */
    if (strcmp(t, "0/0") == 0 || strcmp(t, "0.0.0.0/0") == 0 || strcmp(t, "0.0.0.0/0.0.0.0") == 0 ||
            strcmp(t, "0.0.0.0-255.255.255.255") == 0 || strcmp(t, "0.0.0.0-0.0.0.0/0") == 0) {

        debugs(28,DBG_CRITICAL, "ERROR: '" << t << "' needs to be replaced by the term 'all'.");
        debugs(28,DBG_CRITICAL, "SECURITY NOTICE: Overriding config setting. Using 'all' instead.");
        q->addr1.setAnyAddr();
        q->addr2.setEmpty();
        q->mask.setAnyAddr();
        return q;
    }

    /* Special ACL RHS "ipv4" matches IPv4 Internet
     * A nod to IANA; we include the entire class space in case
     * they manage to find a way to recover and use it */
    if (strcmp(t, "ipv4") == 0) {
        q->mask.setNoAddr();
        q->mask.applyMask(0, AF_INET);
        return q;
    }

    /* Special ACL RHS "ipv6" matches IPv6-Unicast Internet */
    if (strcmp(t, "ipv6") == 0) {
        debugs(28, 9, "aclIpParseIpData: magic 'ipv6' found.");
        r = q; // save head of the list for result.

        /* 0000::/4 is a mix of localhost and obsolete IPv4-mapping space. Not valid outside this host. */

        /* Future global unicast space: 1000::/4 */
        q->addr1 = "1000::";
        q->mask.setNoAddr();
        q->mask.applyMask(4, AF_INET6);

        /* Current global unicast space: 2000::/4 = (2000::/4 - 3000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "2000::";
        q->mask.setNoAddr();
        q->mask.applyMask(3, AF_INET6);

        /* Future global unicast space: 4000::/2 = (4000::/4 - 7000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "4000::";
        q->mask.setNoAddr();
        q->mask.applyMask(2, AF_INET6);

        /* Future global unicast space: 8000::/2 = (8000::/4 - B000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "8000::";
        q->mask.setNoAddr();
        q->mask.applyMask(2, AF_INET6);

        /* Future global unicast space: C000::/3 = (C000::/4 - D000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "C000::";
        q->mask.setNoAddr();
        q->mask.applyMask(3, AF_INET6);

        /* Future global unicast space: E000::/4 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "E000::";
        q->mask.setNoAddr();
        q->mask.applyMask(4, AF_INET6);

        /* F000::/4 is mostly reserved non-unicast. With some exceptions ... */

        /* RFC 4193 Unique-Local unicast space: FC00::/7 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "FC00::";
        q->mask.setNoAddr();
        q->mask.applyMask(7, AF_INET6);

        /* Link-Local unicast space: FE80::/10 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "FE80::";
        q->mask.setNoAddr();
        q->mask.applyMask(10, AF_INET6);

        return r;
    }

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
        struct addrinfo *hp = NULL, *x = NULL;
        struct addrinfo hints;
        Ip::Address *prev_addr = NULL;

        memset(&hints, 0, sizeof(struct addrinfo));

        int errcode = getaddrinfo(addr1,NULL,&hints,&hp);
        if (hp == NULL) {
            delete q;
            if (strcmp(addr1, "::1") == 0) {
                debugs(28, DBG_IMPORTANT, "aclIpParseIpData: IPv6 has not been enabled in host DNS resolver.");
            } else {
                debugs(28, DBG_CRITICAL, "aclIpParseIpData: Bad host/IP: '" << addr1 <<
                       "' in '" << t << "', flags=" << hints.ai_flags <<
                       " : (" << errcode << ") " << gai_strerror(errcode) );
                self_destruct();
            }
            return NULL;
        }

        Q = &q;

        for (x = hp; x != NULL;) {
            if ((r = *Q) == NULL)
                r = *Q = new acl_ip_data;

            /* getaddrinfo given a host has a nasty tendency to return duplicate addr's */
            /* BUT sorted fortunately, so we can drop most of them easily */
            r->addr1 = *x;
            x = x->ai_next;
            if ( prev_addr && r->addr1 == *prev_addr) {
                debugs(28, 3, "aclIpParseIpData: Duplicate host/IP: '" << r->addr1 << "' dropped.");
                delete r;
                *Q = NULL;
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

        if (*Q != NULL) {
            debugs(28, DBG_CRITICAL, "aclIpParseIpData: Bad host/IP: '" << t << "'");
            self_destruct();
            return NULL;
        }

        return q;
    }

    /* ignore IPv6 addresses when built with IPv4-only */
    if ( iptype == AF_INET6 && !Ip::EnableIpv6) {
        debugs(28, DBG_IMPORTANT, "aclIpParseIpData: IPv6 has not been enabled.");
        delete q;
        return NULL;
    }

    /* Decode addr1 */
    if (!*addr1 || !(q->addr1 = addr1)) {
        debugs(28, DBG_CRITICAL, "aclIpParseIpData: unknown first address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode addr2 */
    if (!*addr2)
        q->addr2.setAnyAddr();
    else if (!(q->addr2=addr2) ) {
        debugs(28, DBG_CRITICAL, "aclIpParseIpData: unknown second address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode mask (NULL or empty means a exact host mask) */
    if (!DecodeMask(mask, q->mask, iptype)) {
        debugs(28, DBG_CRITICAL, "aclParseIpData: unknown netmask '" << mask << "' in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    changed = 0;
    changed += q->addr1.applyMask(q->mask);
    changed += q->addr2.applyMask(q->mask);

    if (changed)
        debugs(28, DBG_CRITICAL, "aclIpParseIpData: WARNING: Netmask masks away part of the specified IP in '" << t << "'");

    debugs(28,9, HERE << "Parsed: " << q->addr1 << "-" << q->addr2 << "/" << q->mask << "(/" << q->mask.cidr() <<")");

    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    /* Same as IPv6 (not so trivial to depict) */
    return q;
}

void
ACLIP::parse()
{
    if (data == NULL)
        data = new IPSplay();

    while (char *t = ConfigParser::strtokFile()) {
        acl_ip_data *q = acl_ip_data::FactoryParse(t);

        while (q != NULL) {
            /* pop each result off the list and add it to the data tree individually */
            acl_ip_data *next_node = q->next;
            q->next = NULL;
            if (!data->find(q,acl_ip_data::NetworkCompare))
                data->insert(q, acl_ip_data::NetworkCompare);
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
    data->visit(visitor);
    return visitor.contents;
}

bool
ACLIP::empty() const
{
    return data->empty();
}

int
ACLIP::match(const Ip::Address &clientip)
{
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
    return (result != NULL);
}

acl_ip_data::acl_ip_data() :addr1(), addr2(), mask(), next (NULL) {}

acl_ip_data::acl_ip_data(Ip::Address const &anAddress1, Ip::Address const &anAddress2, Ip::Address const &aMask, acl_ip_data *aNext) : addr1(anAddress1), addr2(anAddress2), mask(aMask), next(aNext) {}

