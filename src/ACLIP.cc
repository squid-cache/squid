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
    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s", inet_ntoa(ip->addr1));

    if (ip->addr2.s_addr != any_addr.s_addr)
        memBufPrintf(&mb, "-%s", inet_ntoa(ip->addr2));

    if (ip->mask.s_addr != no_addr.s_addr)
        memBufPrintf(&mb, "/%s", inet_ntoa(ip->mask));

    wordlistAdd(W, mb.buf);

    memBufClean(&mb);
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

    struct in_addr A = p->addr1;

    const struct in_addr B = q->addr1;

    const struct in_addr C = q->addr2;
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
        debug(28, 0) ("WARNING: '%s' is a subnetwork of "
                      "'%s'\n", buf_n1, buf_n2);
        debug(28, 0) ("WARNING: because of this '%s' is ignored "
                      "to keep splay tree searching predictable\n", buf_a);
        debug(28, 0) ("WARNING: You should probably remove '%s' "
                      "from the ACL named '%s'\n", buf_n1, AclMatchedName);
    }

    return ret;
}

/*
 * Decode a ascii representation (asc) of a IP adress, and place
 * adress and netmask information in addr and mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
bool

acl_ip_data::DecodeAddress(const char *asc, struct in_addr *addr, struct in_addr *mask)
{
    u_int32_t a;
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0;

    switch (sscanf(asc, "%d.%d.%d.%d", &a1, &a2, &a3, &a4))
    {

    case 4:			/* a dotted quad */

        if (!safe_inet_addr(asc, addr)) {
            debug(28, 0) ("DecodeAddress: unsafe IP address: '%s'\n", asc);
            fatal("DecodeAddress: unsafe IP address");
        }

        break;

    case 1:			/* a significant bits value for a mask */

        if (a1 >= 0 && a1 < 33) {
            addr->s_addr = a1 ? htonl(0xfffffffful << (32 - a1)) : 0;
            break;
        }

    default:
        debug(28, 0) ("DecodeAddress: Invalid IP address '%s'\n", asc);
        return 0;		/* This is not valid address */
    }

    if (mask != NULL)
    {		/* mask == NULL if called to decode a netmask */

        /* Guess netmask */
        a = (u_int32_t) ntohl(addr->s_addr);

        if (!(a & 0xFFFFFFFFul))
            mask->s_addr = htonl(0x00000000ul);
        else if (!(a & 0x00FFFFFF))
            mask->s_addr = htonl(0xFF000000ul);
        else if (!(a & 0x0000FFFF))
            mask->s_addr = htonl(0xFFFF0000ul);
        else if (!(a & 0x000000FF))
            mask->s_addr = htonl(0xFFFFFF00ul);
        else
            mask->s_addr = htonl(0xFFFFFFFFul);
    }

    return 1;
}

#define SCAN_ACL1       "%[0123456789.]-%[0123456789.]/%[0123456789.]"
#define SCAN_ACL2       "%[0123456789.]-%[0123456789.]%c"
#define SCAN_ACL3       "%[0123456789.]/%[0123456789.]"
#define SCAN_ACL4       "%[0123456789.]%c"

acl_ip_data *
acl_ip_data::FactoryParse(const char *t)
{
    LOCAL_ARRAY(char, addr2, 256);
    LOCAL_ARRAY(char, mask, 256);
    acl_ip_data *r;
    acl_ip_data **Q;
    char **x;
    char c;
    debug(28, 5) ("aclParseIpData: %s\n", t);
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
    } else if (sscanf(t, SCAN_ACL4, addr1, &c) == 1) {
        addr2[0] = '\0';
        mask[0] = '\0';
    } else if (sscanf(t, "%[^/]/%s", addr1, mask) == 2) {
        addr2[0] = '\0';
    } else if (sscanf(t, "%s", addr1) == 1) {
        /*
         * Note, must use plain gethostbyname() here because at startup
         * ipcache hasn't been initialized
         */

        struct hostent *hp;

        if ((hp = gethostbyname(addr1)) == NULL) {
            debug(28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
            delete q;
            return NULL;
        }

        Q = &q;

        for (x = hp->h_addr_list; x != NULL && *x != NULL; x++) {
            if ((r = *Q) == NULL)
                r = *Q = new acl_ip_data;

            xmemcpy(&r->addr1.s_addr, *x, sizeof(r->addr1.s_addr));

            r->addr2.s_addr = 0;

            r->mask.s_addr = no_addr.s_addr;	/* 255.255.255.255 */

            Q = &r->next;

            debug(28, 3) ("%s --> %s\n", addr1, inet_ntoa(r->addr1));
        }

        return q;
    } else {
        debug(28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
        delete q;
        return NULL;
    }

    /* Decode addr1 */
    if (!DecodeAddress(addr1, &q->addr1, &q->mask)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown first address '%s'\n", addr1);
        delete q;
        return NULL;
    }

    /* Decode addr2 */
    if (*addr2 && !DecodeAddress(addr2, &q->addr2, &q->mask)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown second address '%s'\n", addr2);
        delete q;
        return NULL;
    }

    /* Decode mask */
    if (*mask && !DecodeAddress(mask, &q->mask, NULL)) {
        debug(28, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown netmask '%s'\n", mask);
        delete q;
        return NULL;
    }

    if ((q->addr1.s_addr & q->mask.s_addr) != q->addr1.s_addr ||
            (q->addr2.s_addr & q->mask.s_addr) != q->addr2.s_addr)
        debug(28, 0) ("aclParseIpData: WARNING: Netmask masks away part of the specified IP in '%s'\n", t);

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
    data->destroy(IPSplay::DefaultFree);
}

wordlist *
ACLIP::dump() const
{
    wordlist *w (NULL);
    data->walk (DumpIpListWalkee, &w);
    return w;
}

bool
ACLIP::valid () const
{
    return data != NULL;
}

int

ACLIP::match(struct in_addr &clientip)
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
    debug(28, 3) ("aclMatchIp: '%s' %s\n",
                  inet_ntoa(clientip), splayLastResult ? "NOT found" : "found");
    return !splayLastResult;
}

MemPool *acl_ip_data::Pool(NULL);
void *
acl_ip_data::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (acl_ip_data));

    if (!Pool)
        Pool = memPoolCreate("acl_ip_data", sizeof (acl_ip_data));

    return memPoolAlloc(Pool);
}

void
acl_ip_data::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
acl_ip_data::deleteSelf() const
{
    delete this;
}

acl_ip_data::acl_ip_data () :addr1(any_addr), addr2(any_addr), mask (any_addr), next (NULL) {}

acl_ip_data::acl_ip_data (struct in_addr const &anAddress1, struct in_addr const &anAddress2, struct in_addr const &aMask, acl_ip_data *aNext) : addr1(anAddress1), addr2(anAddress2), mask(aMask), next(aNext){}
