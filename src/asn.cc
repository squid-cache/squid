
/*
 * $Id: asn.cc,v 1.115.2.1 2008/02/25 23:08:50 amosjeffries Exp $
 *
 * DEBUG: section 53    AS Number handling
 * AUTHOR: Duane Wessels, Kostas Anagnostakis
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
 */

#include "squid.h"
#include "CacheManager.h"
#include "radix.h"
#include "HttpRequest.h"
#include "StoreClient.h"
#include "Store.h"
#include "ACL.h"
#include "ACLASN.h"
#include "ACLSourceASN.h"
#include "ACLDestinationASN.h"
#include "ACLDestinationIP.h"
#include "HttpReply.h"
#include "forward.h"
#include "wordlist.h"

#define WHOIS_PORT 43
#define	AS_REQBUF_SZ	4096

/* BEGIN of definitions for radix tree entries */

/* int in memory with length */
typedef u_char m_int[1 + sizeof(unsigned int)];
#define store_m_int(i, m) \
    (i = htonl(i), m[0] = sizeof(m_int), xmemcpy(m+1, &i, sizeof(unsigned int)))
#define get_m_int(i, m) \
    (xmemcpy(&i, m+1, sizeof(unsigned int)), ntohl(i))

/* END of definitions for radix tree entries */

/* Head for ip to asn radix tree */

struct squid_radix_node_head *AS_tree_head;

/* explicit instantiation required for some systems */

template cbdata_type List<int>
::CBDATA_List;

/*
 * Structure for as number information. it could be simply 
 * a list but it's coded as a structure for future
 * enhancements (e.g. expires)
 */

struct as_info
{
    List<int> *as_number;
    time_t expires;		/* NOTUSED */
};

struct ASState
{
    StoreEntry *entry;
    store_client *sc;
    HttpRequest *request;
    int as_number;
    int64_t offset;
    int reqofs;
    char reqbuf[AS_REQBUF_SZ];
    bool dataRead;
};

/** entry into the radix tree */
struct rtentry_t
{
    struct squid_radix_node e_nodes[2];
    as_info *e_info;
    m_int e_addr;
    m_int e_mask;
};

static int asnAddNet(char *, int);

static void asnCacheStart(int as);

static STCB asHandleReply;

static int destroyRadixNode(struct squid_radix_node *rn, void *w);

static int printRadixNode(struct squid_radix_node *rn, void *sentry);

void asnAclInitialize(ACL * acls);

static void asStateFree(void *data);

static void destroyRadixNodeInfo(as_info *);

static OBJH asnStats;

/* PUBLIC */

int
asnMatchIp(List<int> *data, struct IN_ADDR addr)
{
    unsigned long lh;

    struct squid_radix_node *rn;
    as_info *e;
    m_int m_addr;
    List<int> *a = NULL;
    List<int> *b = NULL;
    lh = ntohl(addr.s_addr);
    debugs(53, 3, "asnMatchIp: Called for " << inet_ntoa(addr) << ".");

    if (AS_tree_head == NULL)
        return 0;

    if (addr.s_addr == no_addr.s_addr)
        return 0;

    if (addr.s_addr == any_addr.s_addr)
        return 0;

    store_m_int(lh, m_addr);

    rn = squid_rn_match(m_addr, AS_tree_head);

    if (rn == NULL) {
        debugs(53, 3, "asnMatchIp: Address not in as db.");
        return 0;
    }

    debugs(53, 3, "asnMatchIp: Found in db!");
    e = ((rtentry_t *) rn)->e_info;
    assert(e);

    for (a = data; a; a = a->next)
        for (b = e->as_number; b; b = b->next)
            if (a->element == b->element) {
                debugs(53, 5, "asnMatchIp: Found a match!");
                return 1;
            }

    debugs(53, 5, "asnMatchIp: AS not in as db.");
    return 0;
}

void
ACLASN::prepareForUse()
{
    for (List<int> *i = data; i; i = i->
                                     next)
        asnCacheStart(i->element);
}

/* initialize the radix tree structure */

SQUIDCEXTERN int squid_max_keylen;	/* yuck.. this is in lib/radix.c */

CBDATA_TYPE(ASState);
void
asnInit(void)
{
    static int inited = 0;
    squid_max_keylen = 40;
    CBDATA_INIT_TYPE(ASState);

    if (0 == inited++)
        squid_rn_init();

    squid_rn_inithead(&AS_tree_head, 8);
}

void
asnRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("asndb", "AS Number Database", asnStats, 0, 1);
}

void
asnFreeMemory(void)
{
    squid_rn_walktree(AS_tree_head, destroyRadixNode, AS_tree_head);

    destroyRadixNode((struct squid_radix_node *) 0, (void *) AS_tree_head);
}

static void
asnStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Address    \tAS Numbers\n");
    squid_rn_walktree(AS_tree_head, printRadixNode, sentry);
}

/* PRIVATE */


static void
asnCacheStart(int as)
{
    LOCAL_ARRAY(char, asres, 4096);
    StoreEntry *e;
    HttpRequest *req;
    ASState *asState;
    asState = cbdataAlloc(ASState);
    asState->dataRead = 0;
    debugs(53, 3, "asnCacheStart: AS " << as);
    snprintf(asres, 4096, "whois://%s/!gAS%d", Config.as_whois_server, as);
    asState->as_number = as;
    req = HttpRequest::CreateFromUrl(asres);
    assert(NULL != req);
    asState->request = HTTPMSGLOCK(req);

    if ((e = storeGetPublic(asres, METHOD_GET)) == NULL) {
        e = storeCreateEntry(asres, asres, request_flags(), METHOD_GET);
        asState->sc = storeClientListAdd(e, asState);
        FwdState::fwdStart(-1, e, asState->request);
    } else {

        e->lock()

        ;
        asState->sc = storeClientListAdd(e, asState);
    }

    asState->entry = e;
    asState->offset = 0;
    asState->reqofs = 0;
    StoreIOBuffer readBuffer (AS_REQBUF_SZ, asState->offset, asState->reqbuf);
    storeClientCopy(asState->sc,
                    e,
                    readBuffer,
                    asHandleReply,
                    asState);
}

static void
asHandleReply(void *data, StoreIOBuffer result)
{
    ASState *asState = (ASState *)data;
    StoreEntry *e = asState->entry;
    char *s;
    char *t;
    char *buf = asState->reqbuf;
    int leftoversz = -1;

    debugs(53, 3, "asHandleReply: Called with size=" << (unsigned int)result.length);
    debugs(53, 3, "asHandleReply: buffer='" << buf << "'");

    /* First figure out whether we should abort the request */

    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
        asStateFree(asState);
        return;
    }

    if (result.length == 0 && asState->dataRead) {
        debugs(53, 3, "asHandleReply: Done: " << e->url()  );
        asStateFree(asState);
        return;
    } else if (result.flags.error) {
        debugs(53, 1, "asHandleReply: Called with Error set and size=" << (unsigned int) result.length);
        asStateFree(asState);
        return;
    } else if (HTTP_OK != e->getReply()->sline.status) {
        debugs(53, 1, "WARNING: AS " << asState->as_number << " whois request failed");
        asStateFree(asState);
        return;
    }

    /*
     * Next, attempt to parse our request
     * Remembering that the actual buffer size is retsize + reqofs!
     */
    s = buf;

    while ((size_t)(s - buf) < result.length + asState->reqofs && *s != '\0') {
        while (*s && xisspace(*s))
            s++;

        for (t = s; *t; t++) {
            if (xisspace(*t))
                break;
        }

        if (*t == '\0') {
            /* oof, word should continue on next block */
            break;
        }

        *t = '\0';
        debugs(53, 3, "asHandleReply: AS# " << s << " (" << asState->as_number << ")");
        asnAddNet(s, asState->as_number);
        s = t + 1;
        asState->dataRead = 1;
    }

    /*
     * Next, grab the end of the 'valid data' in the buffer, and figure
     * out how much data is left in our buffer, which we need to keep
     * around for the next request
     */
    leftoversz = (asState->reqofs + result.length) - (s - buf);

    assert(leftoversz >= 0);

    /*
     * Next, copy the left over data, from s to s + leftoversz to the
     * beginning of the buffer
     */
    xmemmove(buf, s, leftoversz);

    /*
     * Next, update our offset and reqofs, and kick off a copy if required
     */
    asState->offset += result.length;

    asState->reqofs = leftoversz;

    debugs(53, 3, "asState->offset = " << asState->offset);

    if (e->store_status == STORE_PENDING) {
        debugs(53, 3, "asHandleReply: store_status == STORE_PENDING: " << e->url()  );
        StoreIOBuffer tempBuffer (AS_REQBUF_SZ - asState->reqofs,
                                  asState->offset,
                                  asState->reqbuf + asState->reqofs);
        storeClientCopy(asState->sc,
                        e,
                        tempBuffer,
                        asHandleReply,
                        asState);
    } else {
        StoreIOBuffer tempBuffer;
        debugs(53, 3, "asHandleReply: store complete, but data received " << e->url()  );
        tempBuffer.offset = asState->offset;
        tempBuffer.length = AS_REQBUF_SZ - asState->reqofs;
        tempBuffer.data = asState->reqbuf + asState->reqofs;
        storeClientCopy(asState->sc,
                        e,
                        tempBuffer,
                        asHandleReply,
                        asState);
    }
}

static void
asStateFree(void *data)
{
    ASState *asState = (ASState *)data;
    debugs(53, 3, "asnStateFree: " << asState->entry->url()  );
    storeUnregister(asState->sc, asState->entry, asState);
    asState->entry->unlock();
    HTTPMSGUNLOCK(asState->request);
    cbdataFree(asState);
}


/* add a network (addr, mask) to the radix tree, with matching AS
 * number */

static int
asnAddNet(char *as_string, int as_number)
{
    rtentry_t *e;

    struct squid_radix_node *rn;
    char dbg1[32], dbg2[32];
    List<int> **Tail = NULL;
    List<int> *q = NULL;
    as_info *asinfo = NULL;

    struct IN_ADDR in_a, in_m;
    long mask, addr;
    char *t;
    int bitl;

    t = strchr(as_string, '/');

    if (t == NULL) {
        debugs(53, 3, "asnAddNet: failed, invalid response from whois server.");
        return 0;
    }

    *t = '\0';
    addr = inet_addr(as_string);
    bitl = atoi(t + 1);

    if (bitl < 0)
        bitl = 0;

    if (bitl > 32)
        bitl = 32;

    mask = bitl ? 0xfffffffful << (32 - bitl) : 0;

    in_a.s_addr = addr;

    in_m.s_addr = mask;

    xstrncpy(dbg1, inet_ntoa(in_a), 32);

    xstrncpy(dbg2, inet_ntoa(in_m), 32);

    addr = ntohl(addr);

    /*mask = ntohl(mask); */
    debugs(53, 3, "asnAddNet: called for " << dbg1 << "/" << dbg2);

    e = (rtentry_t *)xmalloc(sizeof(rtentry_t));

    memset(e, '\0', sizeof(rtentry_t));

    store_m_int(addr, e->e_addr);

    store_m_int(mask, e->e_mask);

    rn = squid_rn_lookup(e->e_addr, e->e_mask, AS_tree_head);

    if (rn != NULL) {
        asinfo = ((rtentry_t *) rn)->e_info;

        if (asinfo->as_number->find(as_number)) {
            debugs(53, 3, "asnAddNet: Ignoring repeated network '" << dbg1 << "/" << bitl << "' for AS " << as_number);
        } else {
            debugs(53, 3, "asnAddNet: Warning: Found a network with multiple AS numbers!");

            for (Tail = &asinfo->as_number; *Tail; Tail = &(*Tail)->next)

                ;
            q = new List<int> (as_number);

            *(Tail) = q;

            e->e_info = asinfo;
        }
    } else {
        q = new List<int> (as_number);
        asinfo = (as_info *)xmalloc(sizeof(as_info));
        asinfo->as_number = q;
        rn = squid_rn_addroute(e->e_addr, e->e_mask, AS_tree_head, e->e_nodes);
        rn = squid_rn_match(e->e_addr, AS_tree_head);
        assert(rn != NULL);
        e->e_info = asinfo;
    }

    if (rn == 0) { 		/* assert might expand to nothing */
        xfree(asinfo);
        delete q;
        xfree(e);
        debugs(53, 3, "asnAddNet: Could not add entry.");
        return 0;
    }

    e->e_info = asinfo;
    return 1;
}

static int

destroyRadixNode(struct squid_radix_node *rn, void *w)
{

    struct squid_radix_node_head *rnh = (struct squid_radix_node_head *) w;

    if (rn && !(rn->rn_flags & RNF_ROOT))
    {
        rtentry_t *e = (rtentry_t *) rn;
        rn = squid_rn_delete(rn->rn_key, rn->rn_mask, rnh);

        if (rn == 0)
            debugs(53, 3, "destroyRadixNode: internal screwup");

        destroyRadixNodeInfo(e->e_info);

        xfree(rn);
    }

    return 1;
}

static void
destroyRadixNodeInfo(as_info * e_info)
{
    List<int> *prev = NULL;
    List<int> *data = e_info->as_number;

    while (data) {
        prev = data;
        data = data->next;
        delete prev;
    }

    delete data;
}

static int
mask_len(u_long mask)
{
    int len = 32;

    if (mask == 0)
        return 0;

    while ((mask & 1) == 0) {
        len--;
        mask >>= 1;
    }

    return len;
}

static int

printRadixNode(struct squid_radix_node *rn, void *_sentry)
{
    StoreEntry *sentry = (StoreEntry *)_sentry;
    rtentry_t *e = (rtentry_t *) rn;
    List<int> *q;
    as_info *asinfo;

    struct IN_ADDR addr;

    struct IN_ADDR mask;
    assert(e);
    assert(e->e_info);
    (void) get_m_int(addr.s_addr, e->e_addr);
    (void) get_m_int(mask.s_addr, e->e_mask);
    storeAppendPrintf(sentry, "%15s/%d\t",
                      inet_ntoa(addr), mask_len(ntohl(mask.s_addr)));
    asinfo = e->e_info;
    assert(asinfo->as_number);

    for (q = asinfo->as_number; q; q = q->next)
        storeAppendPrintf(sentry, " %d", q->element);

    storeAppendPrintf(sentry, "\n");

    return 0;
}

ACLASN::~ACLASN()
{
    if (data)
        delete data;
}

bool

ACLASN::match(struct IN_ADDR toMatch)
{
    return asnMatchIp(data, toMatch);
}

wordlist *
ACLASN::dump()
{
    wordlist *W = NULL;
    char buf[32];
    List<int> *ldata = data;

    while (ldata != NULL) {
        snprintf(buf, sizeof(buf), "%d", ldata->element);
        wordlistAdd(&W, buf);
        ldata = ldata->next;
    }

    return W;
}

bool
ACLASN::empty () const
{
    return data == NULL;
}

void
ACLASN::parse()
{
    List<int> **curlist = &data;
    List<int> **Tail;
    List<int> *q = NULL;
    char *t = NULL;

    for (Tail = curlist; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        q = new List<int> (atoi(t));
        *(Tail) = q;
        Tail = &q->next;
    }
}

ACLData<struct IN_ADDR> *
ACLASN::clone() const
{
    if (data)
        fatal ("cloning of ACLASN not implemented");

    return new ACLASN(*this);
}

/* explicit template instantiation required for some systems */

template class ACLStrategised<struct IN_ADDR>

;

ACL::Prototype ACLASN::SourceRegistryProtoype(&ACLASN::SourceRegistryEntry_, "src_as");

ACLStrategised<struct IN_ADDR> ACLASN::SourceRegistryEntry_(new ACLASN, ACLSourceASNStrategy::Instance(), "src_as");

ACL::Prototype ACLASN::DestinationRegistryProtoype(&ACLASN::DestinationRegistryEntry_, "dst_as");

ACLStrategised<struct IN_ADDR> ACLASN::DestinationRegistryEntry_(new ACLASN, ACLDestinationASNStrategy::Instance(), "dst_as");

int
ACLSourceASNStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    return data->match(checklist->src_addr);
}

ACLSourceASNStrategy *
ACLSourceASNStrategy::Instance()
{
    return &Instance_;
}

ACLSourceASNStrategy ACLSourceASNStrategy::Instance_;


int
ACLDestinationASNStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    const ipcache_addrs *ia = ipcache_gethostbyname(checklist->request->host, IP_LOOKUP_IF_MISS);

    if (ia) {
        for (int k = 0; k < (int) ia->count; k++) {
            if (data->match(ia->in_addrs[k]))
                return 1;
        }

        return 0;
    } else if (!checklist->request->flags.destinationIPLookedUp()) {
        /* No entry in cache, lookup not attempted */
        /* XXX FIXME: allow accessing the acl name here */
        debugs(28, 3, "asnMatchAcl: Can't yet compare '" << "unknown" /*name*/ << "' ACL for '" << checklist->request->host << "'");
        checklist->changeState (DestinationIPLookup::Instance());
    } else {
        return data->match(no_addr);
    }

    return 0;
}

ACLDestinationASNStrategy *
ACLDestinationASNStrategy::Instance()
{
    return &Instance_;
}

ACLDestinationASNStrategy ACLDestinationASNStrategy::Instance_;
