
/*
 * $Id: asn.cc,v 1.86 2002/10/25 07:36:32 robertc Exp $
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
#include "radix.h"
#include "StoreClient.h"
#include "Store.h"

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

/*
 * Structure for as number information. it could be simply 
 * an intlist but it's coded as a structure for future
 * enhancements (e.g. expires)
 */
struct _as_info {
    intlist *as_number;
    time_t expires;		/* NOTUSED */
};

struct _ASState {
    StoreEntry *entry;
    store_client *sc;
    request_t *request;
    int as_number;
    off_t offset;
    int reqofs;
    char reqbuf[AS_REQBUF_SZ];
};

typedef struct _ASState ASState;
typedef struct _as_info as_info;

/* entry into the radix tree */
struct _rtentry {
    struct squid_radix_node e_nodes[2];
    as_info *e_info;
    m_int e_addr;
    m_int e_mask;
};

typedef struct _rtentry rtentry_t;

static int asnAddNet(char *, int);
static void asnCacheStart(int as);
static STCB asHandleReply;
static int destroyRadixNode(struct squid_radix_node *rn, void *w);
static int printRadixNode(struct squid_radix_node *rn, void *sentry);
static void asnAclInitialize(acl * acls);
static void asStateFree(void *data);
static void destroyRadixNodeInfo(as_info *);
static OBJH asnStats;

/* PUBLIC */

int
asnMatchIp(void *data, struct in_addr addr)
{
    unsigned long lh;
    struct squid_radix_node *rn;
    as_info *e;
    m_int m_addr;
    intlist *a = NULL;
    intlist *b = NULL;
    lh = ntohl(addr.s_addr);
    debug(53, 3) ("asnMatchIp: Called for %s.\n", inet_ntoa(addr));

    if (AS_tree_head == NULL)
	return 0;
    if (addr.s_addr == no_addr.s_addr)
	return 0;
    if (addr.s_addr == any_addr.s_addr)
	return 0;
    store_m_int(lh, m_addr);
    rn = squid_rn_match(m_addr, AS_tree_head);
    if (rn == NULL) {
	debug(53, 3) ("asnMatchIp: Address not in as db.\n");
	return 0;
    }
    debug(53, 3) ("asnMatchIp: Found in db!\n");
    e = ((rtentry_t *) rn)->e_info;
    assert(e);
    for (a = (intlist *) data; a; a = a->next)
	for (b = e->as_number; b; b = b->next)
	    if (a->i == b->i) {
		debug(53, 5) ("asnMatchIp: Found a match!\n");
		return 1;
	    }
    debug(53, 5) ("asnMatchIp: AS not in as db.\n");
    return 0;
}

static void
asnAclInitialize(acl * acls)
{
    acl *a;
    intlist *i;
    debug(53, 3) ("asnAclInitialize\n");
    for (a = acls; a; a = a->next) {
	if (a->type != ACL_DST_ASN && a->type != ACL_SRC_ASN)
	    continue;
	for (i = (intlist *)a->data; i; i = i->next)
	    asnCacheStart(i->i);
    }
}

/* initialize the radix tree structure */

extern int squid_max_keylen;	/* yuck.. this is in lib/radix.c */

CBDATA_TYPE(ASState);
void
asnInit(void)
{
    static int inited = 0;
    squid_max_keylen = 40;
    CBDATA_INIT_TYPE(ASState);
    if (0 == inited++)
	squid_rn_init();
    squid_rn_inithead((void **) &AS_tree_head, 8);
    asnAclInitialize(Config.aclList);
    cachemgrRegister("asndb", "AS Number Database", asnStats, 0, 1);
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
    request_t *req;
    ASState *asState;
    StoreIOBuffer readBuffer = EMPTYIOBUFFER;
    asState = cbdataAlloc(ASState);
    debug(53, 3) ("asnCacheStart: AS %d\n", as);
    snprintf(asres, 4096, "whois://%s/!gAS%d", Config.as_whois_server, as);
    asState->as_number = as;
    req = urlParse(METHOD_GET, asres);
    assert(NULL != req);
    asState->request = requestLink(req);
    if ((e = storeGetPublic(asres, METHOD_GET)) == NULL) {
	e = storeCreateEntry(asres, asres, request_flags(), METHOD_GET);
	asState->sc = storeClientListAdd(e, asState);
	fwdStart(-1, e, asState->request);
    } else {
	storeLockObject(e);
	asState->sc = storeClientListAdd(e, asState);
    }
    asState->entry = e;
    asState->offset = 0;
    asState->reqofs = 0;
    readBuffer.offset = asState->offset;
    readBuffer.length = AS_REQBUF_SZ;
    readBuffer.data = asState->reqbuf;
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

    debug(53, 3) ("asHandleReply: Called with size=%u\n", (unsigned int)result.length);
    debug(53, 3) ("asHandleReply: buffer='%s'\n", buf);

    /* First figure out whether we should abort the request */
    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
	asStateFree(asState);
	return;
    }
    if (result.length == 0 && e->mem_obj->inmem_hi > 0) {
	asStateFree(asState);
	return;
    } else if (result.flags.error) {
	debug(53, 1) ("asHandleReply: Called with Error set and size=%u\n", (unsigned int) result.length);
	asStateFree(asState);
	return;
    } else if (HTTP_OK != e->mem_obj->reply->sline.status) {
	debug(53, 1) ("WARNING: AS %d whois request failed\n",
	    asState->as_number);
	asStateFree(asState);
	return;
    }
    /*
     * Next, attempt to parse our request
     * Remembering that the actual buffer size is retsize + reqofs!
     */
    s = buf;
    while (s - buf < (off_t)(result.length + asState->reqofs) && *s != '\0') {
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
	debug(53, 3) ("asHandleReply: AS# %s (%d)\n", s, asState->as_number);
	asnAddNet(s, asState->as_number);
	s = t + 1;
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
    debug(53, 3) ("asState->offset = %ld\n", (long int) asState->offset);
    if (e->store_status == STORE_PENDING) {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	debug(53, 3) ("asHandleReply: store_status == STORE_PENDING: %s\n", storeUrl(e));
	tempBuffer.offset = asState->offset;
	tempBuffer.length = AS_REQBUF_SZ - asState->reqofs;
	tempBuffer.data = asState->reqbuf + asState->reqofs;
	storeClientCopy(asState->sc,
	    e,
	    tempBuffer,
	    asHandleReply,
	    asState);
    } else if (asState->offset < e->mem_obj->inmem_hi) {
	StoreIOBuffer tempBuffer = EMPTYIOBUFFER;
	debug(53, 3) ("asHandleReply: asState->offset < e->mem_obj->inmem_hi %s\n", storeUrl(e));
	tempBuffer.offset = asState->offset;
	tempBuffer.length = AS_REQBUF_SZ - asState->reqofs;
	tempBuffer.data = asState->reqbuf + asState->reqofs;
	storeClientCopy(asState->sc,
	    e,
	    tempBuffer,
	    asHandleReply,
	    asState);
    } else {
	debug(53, 3) ("asHandleReply: Done: %s\n", storeUrl(e));
	asStateFree(asState);
    }
}

static void
asStateFree(void *data)
{
    ASState *asState = (ASState *)data;
    debug(53, 3) ("asnStateFree: %s\n", storeUrl(asState->entry));
    storeUnregister(asState->sc, asState->entry, asState);
    storeUnlockObject(asState->entry);
    requestUnlink(asState->request);
    cbdataFree(asState);
}


/* add a network (addr, mask) to the radix tree, with matching AS
 * number */

static int
asnAddNet(char *as_string, int as_number)
{
    rtentry_t *e = (rtentry_t *)xmalloc(sizeof(rtentry_t));
    struct squid_radix_node *rn;
    char dbg1[32], dbg2[32];
    intlist **Tail = NULL;
    intlist *q = NULL;
    as_info *asinfo = NULL;
    struct in_addr in_a, in_m;
    long mask, addr;
    char *t;
    int bitl;

    t = strchr(as_string, '/');
    if (t == NULL) {
	debug(53, 3) ("asnAddNet: failed, invalid response from whois server.\n");
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
    debug(53, 3) ("asnAddNet: called for %s/%s\n", dbg1, dbg2);
    memset(e, '\0', sizeof(rtentry_t));
    store_m_int(addr, e->e_addr);
    store_m_int(mask, e->e_mask);
    rn = squid_rn_lookup(e->e_addr, e->e_mask, AS_tree_head);
    if (rn != NULL) {
	asinfo = ((rtentry_t *) rn)->e_info;
	if (intlistFind(asinfo->as_number, as_number)) {
	    debug(53, 3) ("asnAddNet: Ignoring repeated network '%s/%d' for AS %d\n",
		dbg1, bitl, as_number);
	} else {
	    debug(53, 3) ("asnAddNet: Warning: Found a network with multiple AS numbers!\n");
	    for (Tail = &asinfo->as_number; *Tail; Tail = &(*Tail)->next);
	    q = (intlist *)xcalloc(1, sizeof(intlist));
	    q->i = as_number;
	    *(Tail) = q;
	    e->e_info = asinfo;
	}
    } else {
	q = (intlist *)xcalloc(1, sizeof(intlist));
	q->i = as_number;
	asinfo = (as_info *)xmalloc(sizeof(asinfo));
	asinfo->as_number = q;
	rn = squid_rn_addroute(e->e_addr, e->e_mask, AS_tree_head, e->e_nodes);
	rn = squid_rn_match(e->e_addr, AS_tree_head);
	assert(rn != NULL);
	e->e_info = asinfo;
    }
    if (rn == 0) {
	xfree(e);
	debug(53, 3) ("asnAddNet: Could not add entry.\n");
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
	    debug(53, 3) ("destroyRadixNode: internal screwup\n");
	destroyRadixNodeInfo(e->e_info);
	xfree(rn);
    }
    return 1;
}

static void
destroyRadixNodeInfo(as_info * e_info)
{
    intlist *prev = NULL;
    intlist *data = e_info->as_number;
    while (data) {
	prev = data;
	data = data->next;
	xfree(prev);
    }
    xfree(data);
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
    intlist *q;
    as_info *asinfo;
    struct in_addr addr;
    struct in_addr mask;
    assert(e);
    assert(e->e_info);
    (void) get_m_int(addr.s_addr, e->e_addr);
    (void) get_m_int(mask.s_addr, e->e_mask);
    storeAppendPrintf(sentry, "%15s/%d\t",
	inet_ntoa(addr), mask_len(ntohl(mask.s_addr)));
    asinfo = e->e_info;
    assert(asinfo->as_number);
    for (q = asinfo->as_number; q; q = q->next)
	storeAppendPrintf(sentry, " %d", q->i);
    storeAppendPrintf(sentry, "\n");
    return 0;
}
