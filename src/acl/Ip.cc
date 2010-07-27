/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/Ip.h"
#include "acl/Checklist.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "wordlist.h"

void *
ACLIP::operator new (size_t byteCount)
{
    fatal ("ACLIP::operator new: unused");
    return (void *)1;
}

void
ACLIP::operator delete (void *address)
{
    fatal ("ACLIP::operator delete: unused");
}

/**
 * Writes an IP ACL data into a buffer, then copies the buffer into the wordlist given
 *
 \param ip	ACL data structure to display
 \param state	wordlist structure which is being generated
 */
void
ACLIP::DumpIpListWalkee(acl_ip_data * const & ip, void *state)
{
    char tmpbuf[ ((MAX_IPSTRLEN*2)+6) ]; // space for 2 IPs and a CIDR mask(3) and seperators(3).
    MemBuf mb;
    wordlist **W = static_cast<wordlist **>(state);
    tmpbuf[0] = '\0';

    mb.init();
    assert(mb.max_capacity > 0 && 1==1 );

    ip->toStr(tmpbuf, sizeof(tmpbuf) );
    assert(mb.max_capacity > 0 && 2==2 );
    mb.append(tmpbuf, strlen(tmpbuf) );
    assert(mb.max_capacity > 0 && 3==3);
    wordlistAdd(W, mb.buf);
    mb.clean();
}

/**
 * print/format an acl_ip_data structure for debugging output.
 *
 \param buf	string buffer to write to
 \param len	size of the buffer available
 */
void
acl_ip_data::toStr(char *buf, int len) const
{
    char *b1 = buf;
    char *b2 = NULL;
    char *b3 = NULL;
    int rlen = 0;

    addr1.NtoA(b1, len - rlen );
    rlen = strlen(buf);
    b2 = buf + rlen;

    if (!addr2.IsAnyAddr()) {
        b2[0] = '-';
        rlen++;
        addr2.NtoA(&(b2[1]), len - rlen );
        rlen = strlen(buf);
    } else
        b2[0] = '\0';

    b3 = buf + rlen;

    if (!mask.IsNoAddr()) {
        b3[0] = '/';
        rlen++;
        int cidr =  mask.GetCIDR() - (addr1.IsIPv4()?96:0);
        snprintf(&(b3[1]), (len-rlen), "%u", (unsigned int)(cidr<0?0:cidr) );
    } else
        b3[0] = '\0';
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
    IpAddress A = p->addr1;

    /* apply netmask */
    A.ApplyMask(q->mask);

    debugs(28,9, "aclIpAddrNetworkCompare: compare: " << p->addr1 << "/" << q->mask << " (" << A << ")  vs " <<
           q->addr1 << "-" << q->addr2 << "/" << q->mask);

    if (q->addr2.IsAnyAddr()) {       /* single address check */

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
        debugs(28, 0, "WARNING: (" << (bina?'B':'A') << ") '" << buf_n1 << "' is a subnetwork of (" << (bina?'A':'B') << ") '" << buf_n2 << "'");
        debugs(28, 0, "WARNING: because of this '" << (bina?buf_n2:buf_n1) << "' is ignored to keep splay tree searching predictable");
        debugs(28, 0, "WARNING: You should probably remove '" << buf_n1 << "' from the ACL named '" << AclMatchedName << "'");
    }

    return ret;
}

/**
 * Decode an ascii representation (asc) of a IP netmask address or CIDR,
 * and place resulting information in mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
bool
acl_ip_data::DecodeMask(const char *asc, IpAddress &mask, int ctype)
{
    char junk;
    int a1 = 0;

    /* default is a mask that doesn't change any IP */
    mask.SetNoAddr();

    if (!asc || !*asc) {
        return true;
    }

    /* An int mask 128, 32 */
    if ((sscanf(asc, "%d%c", &a1, &junk)==1) &&
            (a1 <= 128) && (a1  >= 0)
       ) {
        return mask.ApplyMask(a1, ctype);
    }

    /* dotted notation */
    /* assignment returns true if asc contained an IP address as text */
    if ((mask = asc)) {
        /* HACK: IPv4 netmasks don't cleanly map to IPv6 masks. */
        debugs(28, DBG_CRITICAL, "WARNING: Netmasks are deprecated. Please use CIDR masks instead.");
        if (mask.IsIPv4()) {
            /* locate what CIDR mask was _probably_ meant to be in its native protocol format. */
            /* this will completely crap out with a security fail-open if the admin is playing mask tricks */
            /* however, thats their fault, and we do warn. see bug 2601 for the effects if we don't do this. */
            unsigned int m = mask.GetCIDR();
            debugs(28, DBG_CRITICAL, "WARNING: IPv4 netmasks are particularly nasty when used to compare IPv6 to IPv4 ranges.");
            debugs(28, DBG_CRITICAL, "WARNING: For now we will assume you meant to write /" << m);
            /* reset the mask completely, and crop to the CIDR boundary back properly. */
            mask.SetNoAddr();
            return mask.ApplyMask(m,AF_INET);
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
    IpAddress temp;
    char c;
    unsigned int changed;
    acl_ip_data *q = new acl_ip_data;
    int iptype = AF_UNSPEC;

    debugs(28, 5, "aclIpParseIpData: " << t);

    /* Special ACL RHS "all" matches entire Internet */
    if (strcasecmp(t, "all") == 0) {
        debugs(28, 9, "aclIpParseIpData: magic 'all' found.");
        q->addr1.SetAnyAddr();
        q->addr2.SetEmpty();
        q->mask.SetAnyAddr();
        return q;
    }

    /* Detect some old broken strings equivalent to 'all'.
     * treat them nicely. But be loud until its fixed.  */
    if (strcasecmp(t, "0/0") == 0 || strcasecmp(t, "0.0.0.0/0") == 0 || strcasecmp(t, "0.0.0.0/0.0.0.0") == 0 ||
            strcasecmp(t, "0.0.0.0-255.255.255.255") == 0 || strcasecmp(t, "0.0.0.0-0.0.0.0/0") == 0) {

        debugs(28,DBG_CRITICAL, "ERROR: '" << t << "' needs to be replaced by the term 'all'.");
        debugs(28,DBG_CRITICAL, "SECURITY NOTICE: Overriding config setting. Using 'all' instead.");
        q->addr1.SetAnyAddr();
        q->addr2.SetEmpty();
        q->mask.SetAnyAddr();
        return q;
    }

    /* Special ACL RHS "ipv4" matches IPv4 Internet
     * A nod to IANA; we include the entire class space in case
     * they manage to find a way to recover and use it */
    if (strcasecmp(t, "ipv4") == 0) {
        q->mask.SetNoAddr();
        q->mask.ApplyMask(0, AF_INET);
        return q;
    }

    /* Special ACL RHS "ipv6" matches IPv6-Unicast Internet */
    if (strcasecmp(t, "ipv6") == 0) {
        debugs(28, 9, "aclIpParseIpData: magic 'ipv6' found.");
        r = q; // save head of the list for result.

        /* 0000::/4 is a mix of localhost and obsolete IPv4-mapping space. Not valid outside this host. */

        /* Future global unicast space: 1000::/4 */
        q->addr1 = "1000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(4, AF_INET6);

        /* Current global unicast space: 2000::/4 = (2000::/4 - 3000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "2000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(3, AF_INET6);

        /* Future global unicast space: 4000::/2 = (4000::/4 - 7000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "4000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(2, AF_INET6);

        /* Future global unicast space: 8000::/2 = (8000::/4 - B000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "8000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(2, AF_INET6);

        /* Future global unicast space: C000::/3 = (C000::/4 - D000::/4) */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "C000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(3, AF_INET6);

        /* Future global unicast space: E000::/4 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "E000::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(4, AF_INET6);

        /* F000::/4 is mostly reserved non-unicast. With some exceptions ... */

        /* RFC 4193 Unique-Local unicast space: FC00::/7 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "FC00::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(7, AF_INET6);

        /* Link-Local unicast space: FE80::/10 */
        q->next = new acl_ip_data;
        q = q->next;
        q->addr1 = "FE80::";
        q->mask.SetNoAddr();
        q->mask.ApplyMask(10, AF_INET6);

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
         * Note, must use plain xgetaddrinfo() here because at startup
         * ipcache hasn't been initialized
         * TODO: offload this to one of the IpAddress lookups.
         */

        debugs(28, 5, "aclIpParseIpData: Lookup Host/IP " << addr1);
        struct addrinfo *hp = NULL, *x = NULL;
        struct addrinfo hints;
        IpAddress *prev_addr = NULL;

        memset(&hints, 0, sizeof(struct addrinfo));

        if ( iptype != AF_UNSPEC ) {
            hints.ai_flags |= AI_NUMERICHOST;
        }

#if 0
        if (Ip::EnableIpv6&IPV6_SPECIAL_V4MAPPING)
            hints.ai_flags |= AI_V4MAPPED | AI_ALL;
#endif

        int errcode = xgetaddrinfo(addr1,NULL,&hints,&hp);
        if (hp == NULL) {
            debugs(28, 0, "aclIpParseIpData: Bad host/IP: '" << addr1 <<
                   "' in '" << t << "', flags=" << hints.ai_flags <<
                   " : (" << errcode << ") " << xgai_strerror(errcode) );
            self_destruct();
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

            r->addr2.SetAnyAddr();
            r->mask.SetNoAddr();

            Q = &r->next;

            debugs(28, 3, "" << addr1 << " --> " << r->addr1 );
        }

        if (*Q != NULL) {
            debugs(28, 0, "aclIpParseIpData: Bad host/IP: '" << t << "'");
            self_destruct();
            return NULL;
        }

        xfreeaddrinfo(hp);

        return q;
    }

    /* ignore IPv6 addresses when built with IPv4-only */
    if ( iptype == AF_INET6 && !Ip::EnableIpv6) {
        debugs(28, DBG_IMPORTANT, "aclIpParseIpData: IPv6 has not been enabled.");
        return NULL;
    }

    /* Decode addr1 */
    if (!*addr1 || !(q->addr1 = addr1)) {
        debugs(28, 0, "aclIpParseIpData: unknown first address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode addr2 */
    if (!*addr2)
        q->addr2.SetAnyAddr();
    else if (!(q->addr2=addr2) ) {
        debugs(28, 0, "aclIpParseIpData: unknown second address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode mask (NULL or empty means a exact host mask) */
    if (!DecodeMask(mask, q->mask, iptype)) {
        debugs(28, 0, "aclParseIpData: unknown netmask '" << mask << "' in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    changed = 0;
    changed += q->addr1.ApplyMask(q->mask);
    changed += q->addr2.ApplyMask(q->mask);

    if (changed)
        debugs(28, 0, "aclIpParseIpData: WARNING: Netmask masks away part of the specified IP in '" << t << "'");

    debugs(28,9, HERE << "Parsed: " << q->addr1 << "-" << q->addr2 << "/" << q->mask << "(/" << q->mask.GetCIDR() <<")");

    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    /* Same as IPv6 (not so trivial to depict) */
    return q;
}

void
ACLIP::parse()
{
    char *t = NULL;

    while ((t = strtokFile())) {
        acl_ip_data *q = acl_ip_data::FactoryParse(t);

        while (q != NULL) {
            /* pop each result off the list and add it to the data tree individually */
            acl_ip_data *next_node = q->next;
            q->next = NULL;
            data = data->insert(q, acl_ip_data::NetworkCompare);
            q = next_node;
        }
    }
}

ACLIP::~ACLIP()
{
    if (data)
        data->destroy(IPSplay::DefaultFree);
}

wordlist *
ACLIP::dump() const
{
    wordlist *w = NULL;
    data->walk (DumpIpListWalkee, &w);
    return w;
}

bool
ACLIP::empty () const
{
    return data->empty();
}

int
ACLIP::match(IpAddress &clientip)
{
    static acl_ip_data ClientAddress;
    /*
     * aclIpAddrNetworkCompare() takes two acl_ip_data pointers as
     * arguments, so we must create a fake one for the client's IP
     * address. Since we are scanning for a single IP mask and addr2
     * MUST be set to empty.
     */
    ClientAddress.addr1 = clientip;
    ClientAddress.addr2.SetEmpty();
    ClientAddress.mask.SetEmpty();

    data = data->splay(&ClientAddress, aclIpAddrNetworkCompare);
    debugs(28, 3, "aclIpMatchIp: '" << clientip << "' " << (splayLastResult ? "NOT found" : "found"));
    return !splayLastResult;
}

acl_ip_data::acl_ip_data () :addr1(), addr2(), mask(), next (NULL) {}

acl_ip_data::acl_ip_data (IpAddress const &anAddress1, IpAddress const &anAddress2, IpAddress const &aMask, acl_ip_data *aNext) : addr1(anAddress1), addr2(anAddress2), mask(aMask), next(aNext) {}
