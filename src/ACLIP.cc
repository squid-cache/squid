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
#include "ACLIP.h"
#include "ACLChecklist.h"
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

void
ACLIP::DumpIpListWalkee(acl_ip_data * const & ip, void *state)
{
    MemBuf mb;
    wordlist **W = static_cast<wordlist **>(state);
    mb.init();
    mb.Printf("%s", inet_ntoa(ip->addr1));

    if (ip->addr2.s_addr != any_addr.s_addr)
        mb.Printf("-%s", inet_ntoa(ip->addr2));

    if (ip->mask.s_addr != no_addr.s_addr)
        mb.Printf("/%s", inet_ntoa(ip->mask));

    wordlistAdd(W, mb.buf);

    mb.clean();
}

/*
 * aclIpDataToStr - print/format an acl_ip_data structure for
 * debugging output.
 */
void
acl_ip_data::toStr(char *buf, int len) const
{
    char b1[20];
    char b2[20];
    char b3[20];
    snprintf(b1, 20, "%s", inet_ntoa(addr1));

    if (addr2.s_addr != any_addr.s_addr)
        snprintf(b2, 20, "-%s", inet_ntoa(addr2));
    else
        b2[0] = '\0';

    if (mask.s_addr != no_addr.s_addr)
        snprintf(b3, 20, "/%s", inet_ntoa(mask));
    else
        b3[0] = '\0';

    snprintf(buf, len, "%s%s%s", b1, b2, b3);
}

/*
 * aclIpAddrNetworkCompare - The guts of the comparison for IP ACLs.
 * The first argument (a) is a "host" address, i.e. the IP address
 * of a cache client.  The second argument (b) is a "network" address
 * that might have a subnet and/or range.  We mask the host address
 * bits with the network subnet mask.
 */
/*
 * aclIpAddrNetworkCompare - The comparison function used for ACL
 * matching checks.  The first argument (a) is a "host" address,
 * i.e.  the IP address of a cache client.  The second argument (b)
 * is an entry in some address-based access control element.  This
 * function is called via ACLIP::match() and the splay library.
 */
int
aclIpAddrNetworkCompare(acl_ip_data * const &p, acl_ip_data * const &q)
{

    struct IN_ADDR A = p->addr1;

    const struct IN_ADDR B = q->addr1;

    const struct IN_ADDR C = q->addr2;
    A.s_addr &= q->mask.s_addr;	/* apply netmask */

    if (C.s_addr == 0) {	/* single address check */

        if (ntohl(A.s_addr) > ntohl(B.s_addr))
            return 1;
        else if (ntohl(A.s_addr) < ntohl(B.s_addr))
            return -1;
        else
            return 0;
    } else {			/* range address check */

        if (ntohl(A.s_addr) > ntohl(C.s_addr))
            return  1;
        else if (ntohl(A.s_addr) < ntohl(B.s_addr))
            return -1;
        else
            return 0;
    }
}


/*
 * acl_ip_data::NetworkCompare - Compare two acl_ip_data entries.  Strictly
 * used by the splay insertion routine.  It emits a warning if it
 * detects a "collision" or overlap that would confuse the splay
 * sorting algorithm.  Much like aclDomainCompare.
 */
int
acl_ip_data::NetworkCompare(acl_ip_data * const & a, acl_ip_data * const &b)
{
    int ret;
    ret = aclIpAddrNetworkCompare(b, a);

    if (ret != 0) {
        ret = aclIpAddrNetworkCompare(a, b);
    }

    if (ret == 0) {
        char buf_n1[60];
        char buf_n2[60];
        char buf_a[60];
        b->toStr(buf_n1, 60);
        a->toStr(buf_n2, 60);
        a->toStr(buf_a, 60);
        /* TODO: this warning may display the wrong way around */
        debugs(28, 0, "WARNING: '" << buf_n1 <<
               "' is a subnetwork of '" << buf_n2 << "'");
        debugs(28, 0, "WARNING: because of this '" << buf_a <<
               "' is ignored to keep splay tree searching predictable");
        debugs(28, 0, "WARNING: You should probably remove '" << buf_n1 <<
               "' from the ACL named '" << AclMatchedName << "'");
    }

    return ret;
}

/*
 * Decode a ascii representation (asc) of a IP adress, and place
 * adress and netmask information in addr and mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
bool

acl_ip_data::DecodeMask(const char *asc, struct IN_ADDR *mask)
{
    char junk;
    int a1 = 0;

    if (!asc || !*asc)
    {
        mask->s_addr = htonl(0xFFFFFFFFul);
        return 1;
    }

    if (sscanf(asc, "%d%c", &a1, &junk) == 1 && a1 >= 0 && a1 < 33)
    {		/* a significant bits value for a mask */
        mask->s_addr = a1 ? htonl(0xfffffffful << (32 - a1)) : 0;
        return 1;
    }

    /* dotted notation */
    if (safe_inet_addr(asc, mask))
        return 1;

    return 0;
}

#define SCAN_ACL1       "%[0123456789.]-%[0123456789.]/%[0123456789.]"
#define SCAN_ACL2       "%[0123456789.]-%[0123456789.]%c"
#define SCAN_ACL3       "%[0123456789.]/%[0123456789.]"

acl_ip_data *
acl_ip_data::FactoryParse(const char *t)
{
    LOCAL_ARRAY(char, addr2, 256);
    LOCAL_ARRAY(char, mask, 256);
    acl_ip_data *r;
    acl_ip_data **Q;
    char **x;
    char c;
    debugs(28, 5, "aclParseIpData: " << t);
    acl_ip_data *q = new acl_ip_data;

    if (!strcasecmp(t, "all")) {
        q->addr1.s_addr = 0;
        q->addr2.s_addr = 0;
        q->mask.s_addr = 0;
        return q;
    }

    LOCAL_ARRAY(char, addr1, 256);

    if (sscanf(t, SCAN_ACL1, addr1, addr2, mask) == 3) {
        (void) 0;
    } else if (sscanf(t, SCAN_ACL2, addr1, addr2, &c) == 2) {
        mask[0] = '\0';
    } else if (sscanf(t, SCAN_ACL3, addr1, mask) == 2) {
        addr2[0] = '\0';
    } else if (sscanf(t, "%[^/]/%s", addr1, mask) == 2) {
        addr2[0] = '\0';
    } else if (sscanf(t, "%s", addr1) == 1) {
        addr2[0] = '\0';
        mask[0] = '\0';
    }

    if (!*addr2) {
        /*
         * Note, must use plain gethostbyname() here because at startup
         * ipcache hasn't been initialized
         */

        struct hostent *hp;

        if ((hp = gethostbyname(addr1)) == NULL) {
            debugs(28, 0, "aclParseIpData: Bad host/IP: '" << t << "'");
            self_destruct();
        }

        Q = &q;

        for (x = hp->h_addr_list; x != NULL && *x != NULL; x++) {
            if ((r = *Q) == NULL)
                r = *Q = new acl_ip_data;

            xmemcpy(&r->addr1.s_addr, *x, sizeof(r->addr1.s_addr));

            r->addr2.s_addr = 0;

            if (!DecodeMask(mask, &r->mask)) {
                debugs(28, 0, "aclParseIpData: unknown netmask '" << mask << "' in '" << t << "'");
                delete r;
                *Q = NULL;
                self_destruct();
                continue;
            }


            Q = &r->next;

            debugs(28, 3, "" << addr1 << " --> " << inet_ntoa(r->addr1));
        }

        if (*Q != NULL) {
            debugs(28, 0, "aclParseIpData: Bad host/IP: '" << t << "'");
            self_destruct();
        }

        return q;
    }

    /* Decode addr1 */
    if (!safe_inet_addr(addr1, &q->addr1)) {
        debugs(28, 0, "aclParseIpData: unknown first address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode addr2 */
    if (!safe_inet_addr(addr2, &q->addr2)) {
        debugs(28, 0, "aclParseIpData: unknown second address in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    /* Decode mask */
    if (!DecodeMask(mask, &q->mask)) {
        debugs(28, 0, "aclParseIpData: unknown netmask '" << mask << "' in '" << t << "'");
        delete q;
        self_destruct();
        return NULL;
    }

    if ((q->addr1.s_addr & q->mask.s_addr) != q->addr1.s_addr ||
            (q->addr2.s_addr & q->mask.s_addr) != q->addr2.s_addr)
        debugs(28, 0, "aclParseIpData: WARNING: Netmask masks away part of the specified IP in '" << t << "'");

    q->addr1.s_addr &= q->mask.s_addr;

    q->addr2.s_addr &= q->mask.s_addr;

    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
    return q;
}

void
ACLIP::parse()
{
    char *t = NULL;

    while ((t = strtokFile())) {
        acl_ip_data *q = acl_ip_data::FactoryParse(t);

        while (q != NULL) {
            data = data->insert(q, acl_ip_data::NetworkCompare);
            q = q->next;
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

ACLIP::match(struct IN_ADDR &clientip)
{
    static acl_ip_data ClientAddress (any_addr, any_addr, no_addr, NULL);
    /*
     * aclIpAddrNetworkCompare() takes two acl_ip_data pointers as
     * arguments, so we must create a fake one for the client's IP
     * address, and use a /32 netmask.  However, the current code
     * probably only accesses the addr1 element of this argument,
     * so it might be possible to leave addr2 and mask unset.
     */
    ClientAddress.addr1 = clientip;
    acl_ip_data *ClientAddressPointer = &ClientAddress;
    data = data->splay(ClientAddressPointer, aclIpAddrNetworkCompare);
    debugs(28, 3, "aclMatchIp: '" << inet_ntoa(clientip) << "' " << (splayLastResult ? "NOT found" : "found"));
    return !splayLastResult;
}

acl_ip_data::acl_ip_data () :addr1(any_addr), addr2(any_addr), mask (any_addr), next (NULL) {}

acl_ip_data::acl_ip_data (struct IN_ADDR const &anAddress1, struct IN_ADDR const &anAddress2, struct IN_ADDR const &aMask, acl_ip_data *aNext) : addr1(anAddress1), addr2(anAddress2), mask(aMask), next(aNext){}
