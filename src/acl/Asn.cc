/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 53    AS Number handling */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Asn.h"
#include "acl/Checklist.h"
#include "acl/DestinationAsn.h"
#include "acl/DestinationIp.h"
#include "acl/SourceAsn.h"
#include "acl/Strategised.h"
#include "FwdState.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ipcache.h"
#include "MasterXaction.h"
#include "mgr/Registration.h"
#include "radix.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StoreClient.h"

#ifndef AS_REQBUF_SZ
#define AS_REQBUF_SZ    4096
#endif

/* BEGIN of definitions for radix tree entries */

/* 32/128 bits address in memory with length */
class m_ADDR
{
public:
    uint8_t len;
    Ip::Address addr;

    m_ADDR() : len(sizeof(Ip::Address)) {};
};

/* END of definitions for radix tree entries */

/* Head for ip to asn radix tree */

struct squid_radix_node_head *AS_tree_head;

/* explicit instantiation required for some systems */

/// \cond AUTODOCS_IGNORE
template cbdata_type CbDataList<int>::CBDATA_CbDataList;
/// \endcond

/**
 * Structure for as number information. it could be simply
 * a list but it's coded as a structure for future
 * enhancements (e.g. expires)
 */
struct as_info {
    CbDataList<int> *as_number;
    time_t expires;     /* NOTUSED */
};

class ASState
{
    CBDATA_CLASS(ASState);

public:
    ASState() {
        memset(reqbuf, 0, sizeof(reqbuf));
    }
    ~ASState() {
        if (entry) {
            debugs(53, 3, entry->url());
            storeUnregister(sc, entry, this);
            entry->unlock("~ASState");
        }
    }

public:
    StoreEntry *entry = nullptr;
    store_client *sc = nullptr;
    HttpRequest::Pointer request;
    int as_number = 0;
    int64_t offset = 0;
    int reqofs = 0;
    char reqbuf[AS_REQBUF_SZ];
    bool dataRead = false;
};

CBDATA_CLASS_INIT(ASState);

/** entry into the radix tree */
struct rtentry_t {
    struct squid_radix_node e_nodes[2];
    as_info *e_info;
    m_ADDR e_addr;
    m_ADDR e_mask;
};

static int asnAddNet(char *, int);

static void asnCacheStart(int as);

static STCB asHandleReply;

#if defined(__cplusplus)
extern "C" {
#endif

static int destroyRadixNode(struct squid_radix_node *rn, void *w);
static int printRadixNode(struct squid_radix_node *rn, void *sentry);

#if defined(__cplusplus)
}
#endif

void asnAclInitialize(ACL * acls);

static void destroyRadixNodeInfo(as_info *);

static OBJH asnStats;

/* PUBLIC */

int
asnMatchIp(CbDataList<int> *data, Ip::Address &addr)
{
    struct squid_radix_node *rn;
    as_info *e;
    m_ADDR m_addr;
    CbDataList<int> *a = NULL;
    CbDataList<int> *b = NULL;

    debugs(53, 3, "asnMatchIp: Called for " << addr );

    if (AS_tree_head == NULL)
        return 0;

    if (addr.isNoAddr())
        return 0;

    if (addr.isAnyAddr())
        return 0;

    m_addr.addr = addr;

    rn = squid_rn_match(&m_addr, AS_tree_head);

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
    for (CbDataList<int> *i = data; i; i = i->
                                           next)
        asnCacheStart(i->element);
}

static void
asnRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("asndb", "AS Number Database", asnStats, 0, 1);
}

/* initialize the radix tree structure */

SQUIDCEXTERN int squid_max_keylen;  /* yuck.. this is in lib/radix.c */

void
asnInit(void)
{
    static bool inited = false;
    squid_max_keylen = 40;

    if (!inited) {
        inited = true;
        squid_rn_init();
    }

    squid_rn_inithead(&AS_tree_head, 8);

    asnRegisterWithCacheManager();
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
    AnyP::Uri whoisUrl(AnyP::PROTO_WHOIS);
    whoisUrl.host(Config.as_whois_server);
    whoisUrl.defaultPort();

    SBuf asPath("/!gAS");
    asPath.appendf("%d", as);
    whoisUrl.path(asPath);

    debugs(53, 3, "AS " << as);
    ASState *asState = new ASState;
    asState->as_number = as;
    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initAsn);
    asState->request = new HttpRequest(mx);
    asState->request->url = whoisUrl;
    asState->request->method = Http::METHOD_GET;

    // XXX: performance regression, c_str() reallocates
    const auto asres = xstrdup(whoisUrl.absolute().c_str());

    // XXX: Missing a hittingRequiresCollapsing() && startCollapsingOn() check.
    auto e = storeGetPublic(asres, Http::METHOD_GET);
    if (!e) {
        e = storeCreateEntry(asres, asres, RequestFlags(), Http::METHOD_GET);
        asState->sc = storeClientListAdd(e, asState);
        FwdState::fwdStart(Comm::ConnectionPointer(), e, asState->request.getRaw());
    } else {
        e->lock("Asn");
        asState->sc = storeClientListAdd(e, asState);
    }
    xfree(asres);

    asState->entry = e;
    StoreIOBuffer readBuffer (AS_REQBUF_SZ, asState->offset, asState->reqbuf);
    storeClientCopy(asState->sc, e, readBuffer, asHandleReply, asState);
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
        delete asState;
        return;
    }

    if (result.length == 0 && asState->dataRead) {
        debugs(53, 3, "asHandleReply: Done: " << e->url());
        delete asState;
        return;
    } else if (result.flags.error) {
        debugs(53, DBG_IMPORTANT, "asHandleReply: Called with Error set and size=" << (unsigned int) result.length);
        delete asState;
        return;
    } else if (e->mem().baseReply().sline.status() != Http::scOkay) {
        debugs(53, DBG_IMPORTANT, "WARNING: AS " << asState->as_number << " whois request failed");
        delete asState;
        return;
    }

    /*
     * Next, attempt to parse our request
     * Remembering that the actual buffer size is retsize + reqofs!
     */
    s = buf;

    while ((size_t)(s - buf) < result.length + asState->reqofs && *s != '\0') {
        while (*s && xisspace(*s))
            ++s;

        for (t = s; *t; ++t) {
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
        asState->dataRead = true;
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
    memmove(buf, s, leftoversz);

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

/**
 * add a network (addr, mask) to the radix tree, with matching AS number
 */
static int
asnAddNet(char *as_string, int as_number)
{
    struct squid_radix_node *rn;
    CbDataList<int> **Tail = NULL;
    CbDataList<int> *q = NULL;
    as_info *asinfo = NULL;

    Ip::Address mask;
    Ip::Address addr;
    char *t;
    int bitl;

    t = strchr(as_string, '/');

    if (t == NULL) {
        debugs(53, 3, "asnAddNet: failed, invalid response from whois server.");
        return 0;
    }

    *t = '\0';
    addr = as_string;
    bitl = atoi(t + 1);

    if (bitl < 0)
        bitl = 0;

    // INET6 TODO : find a better way of identifying the base IPA family for mask than this.
    t = strchr(as_string, '.');

    // generate Netbits Format Mask
    mask.setNoAddr();
    mask.applyMask(bitl, (t!=NULL?AF_INET:AF_INET6) );

    debugs(53, 3, "asnAddNet: called for " << addr << "/" << mask );

    rtentry_t *e = (rtentry_t *)xcalloc(1, sizeof(rtentry_t));

    e->e_addr.addr = addr;

    e->e_mask.addr = mask;

    rn = squid_rn_lookup(&e->e_addr, &e->e_mask, AS_tree_head);

    if (rn != NULL) {
        asinfo = ((rtentry_t *) rn)->e_info;

        if (asinfo->as_number->find(as_number)) {
            debugs(53, 3, "asnAddNet: Ignoring repeated network '" << addr << "/" << bitl << "' for AS " << as_number);
        } else {
            debugs(53, 3, "asnAddNet: Warning: Found a network with multiple AS numbers!");

            for (Tail = &asinfo->as_number; *Tail; Tail = &(*Tail)->next);
            q = new CbDataList<int> (as_number);

            *(Tail) = q;

            e->e_info = asinfo;
        }
    } else {
        q = new CbDataList<int> (as_number);
        asinfo = (as_info *)xmalloc(sizeof(as_info));
        asinfo->as_number = q;
        squid_rn_addroute(&e->e_addr, &e->e_mask, AS_tree_head, e->e_nodes);
        rn = squid_rn_match(&e->e_addr, AS_tree_head);
        assert(rn != NULL);
        e->e_info = asinfo;
    }

    if (rn == 0) {      /* assert might expand to nothing */
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

    if (rn && !(rn->rn_flags & RNF_ROOT)) {
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
    CbDataList<int> *prev = NULL;
    CbDataList<int> *data = e_info->as_number;

    while (data) {
        prev = data;
        data = data->next;
        delete prev;
    }
}

static int
printRadixNode(struct squid_radix_node *rn, void *_sentry)
{
    StoreEntry *sentry = (StoreEntry *)_sentry;
    rtentry_t *e = (rtentry_t *) rn;
    CbDataList<int> *q;
    as_info *asinfo;
    char buf[MAX_IPSTRLEN];
    Ip::Address addr;
    Ip::Address mask;

    assert(e);
    assert(e->e_info);
    addr = e->e_addr.addr;
    mask = e->e_mask.addr;
    storeAppendPrintf(sentry, "%s/%d\t",
                      addr.toStr(buf, MAX_IPSTRLEN),
                      mask.cidr() );
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

ACLASN::match(Ip::Address toMatch)
{
    return asnMatchIp(data, toMatch);
}

SBufList
ACLASN::dump() const
{
    SBufList sl;

    CbDataList<int> *ldata = data;

    while (ldata != NULL) {
        SBuf s;
        s.Printf("%d", ldata->element);
        sl.push_back(s);
        ldata = ldata->next;
    }

    return sl;
}

bool
ACLASN::empty () const
{
    return data == NULL;
}

void
ACLASN::parse()
{
    CbDataList<int> **curlist = &data;
    CbDataList<int> **Tail;
    CbDataList<int> *q = NULL;
    char *t = NULL;

    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = ConfigParser::strtokFile())) {
        q = new CbDataList<int> (atoi(t));
        *(Tail) = q;
        Tail = &q->next;
    }
}

ACLData<Ip::Address> *
ACLASN::clone() const
{
    if (data)
        fatal ("cloning of ACLASN not implemented");

    return new ACLASN(*this);
}

/* explicit template instantiation required for some systems */

template class ACLStrategised<Ip::Address>;

int
ACLSourceASNStrategy::match (ACLData<Ip::Address> * &data, ACLFilledChecklist *checklist)
{
    return data->match(checklist->src_addr);
}

int
ACLDestinationASNStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    const ipcache_addrs *ia = ipcache_gethostbyname(checklist->request->url.host(), IP_LOOKUP_IF_MISS);

    if (ia) {
        for (const auto &ip: ia->goodAndBad()) {
            if (data->match(ip))
                return 1;
        }

        return 0;

    } else if (!checklist->request->flags.destinationIpLookedUp) {
        /* No entry in cache, lookup not attempted */
        debugs(28, 3, "can't yet compare '" << AclMatchedName << "' ACL for " << checklist->request->url.host());
        if (checklist->goAsync(DestinationIPLookup::Instance()))
            return -1;
        // else fall through to noaddr match, hiding the lookup failure (XXX)
    }
    Ip::Address noaddr;
    noaddr.setNoAddr();
    return data->match(noaddr);
}

