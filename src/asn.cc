/*
 *
 * DEBUG: section 53    AS Number handling
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

#define WHOIS_PORT 43

/* BEGIN of definitions for radix tree entries */

typedef u_char m_int[1 + sizeof(unsigned int)];		/* int in memory with length */
#define store_m_int(i, m) \
    (i = htonl(i), m[0] = sizeof(m_int), memcpy(m+1, &i, sizeof(unsigned int)))
#define get_m_int(i, m) \
    (memcpy(&i, m+1, sizeof(unsigned int)), ntohl(i))

/* END of definitions for radix tree entries */

/* Head for ip to asn radix tree */
struct radix_node_head *AS_tree_head;

struct _whoisState {
    StoreEntry *entry;
    request_t *request;
};

/*
 * Structure for as number information. it could be simply 
 * an intlist but it's coded as a structure for future
 * enhancements (e.g. expires)
 */
struct _as_info {
    intlist *as_number;
    time_t expires;
};

struct _ASState {
    StoreEntry *entry;
    request_t *request;
    int as_number;
};

typedef struct _ASState ASState;
typedef struct _as_info as_info;
typedef struct _whoisState whoisState;

/* entry into the radix tree */
struct _rtentry {
    struct radix_node e_nodes[2];
    as_info *e_info;
    m_int e_addr;
    m_int e_mask;
};

typedef struct _rtentry rtentry;

static int asnAddNet(char *, int);
static void asnCacheStart(int as);
static PF whoisClose;
static CNCB whoisConnectDone;
static PF whoisReadReply;
static STCB asHandleReply;
static int destroyRadixNode(struct radix_node *rn, void *w);

static void destroyRadixNodeInfo(as_info *);

/*static int destroyRadixNode(struct radix_node *,caddr_t); */
extern struct radix_node *rn_lookup(void *, void *, void *);


/* PUBLIC */

int
asnMatchIp(void *data, struct in_addr addr)
{
    unsigned long lh;
    struct radix_node *rn;
    as_info *e;
    m_int m_addr;
    intlist *a = NULL;
    intlist *b = NULL;
    lh = ntohl(addr.s_addr);
    debug(53, 4) ("asnMatchIp: Called for %s.\n", inet_ntoa(addr));

    if (AS_tree_head == 0 || &addr == &no_addr)
	return 0;
    store_m_int(lh, m_addr);
    rn = rn_match(m_addr, AS_tree_head);
    if (rn == 0) {
	debug(53, 4) ("asnMatchIp: Address not in as db.\n");
	return 0;
    }
    debug(53, 4) ("asnMatchIp: Found in db!\n");
    e = ((rtentry *) rn)->e_info;
    for (a = (intlist *) data; a; a = a->next)
	for (b = e->as_number; b; b = b->next)
	    if (a->i == b->i) {
		debug(53, 5) ("asnMatchIp: Found a match!\n");
		return 1;
	    }
    debug(53, 5) ("asnMatchIp: AS not in as db.\n");
    return 0;
}

void
asnAclInitialize(acl * acls)
{
    acl *a;
    intlist *i;
    debug(53, 1) ("asnAclInitialize: STARTING\n");
    for (a = acls; a; a = a->next) {
	if (a->type != ACL_DST_ASN && a->type != ACL_SRC_ASN)
	    continue;
	for (i = a->data; i; i = i->next)
	    asnCacheStart(i->i);
    }
}

/* initialize the radix tree structure */

void
asnInit(void)
{
    extern int max_keylen;
    max_keylen = 40;
    rn_init();
    rn_inithead((void **) &AS_tree_head, 8);
}

void
asnFreeMemory(void)
{
    debug(0, 0) ("asnFreeMemory: Calling asnCleanup()!\n");

	/* XXX - Cleanup is enough.   */ 

    asnCleanup();
}

void
asnCleanup()
{
    rn_walktree(AS_tree_head, destroyRadixNode, AS_tree_head);
    destroyRadixNode((struct radix_node *) 0, (void *) AS_tree_head);
}

/* PRIVATE */


static void
asnCacheStart(int as)
{
    LOCAL_ARRAY(char, asres, 4096);
    const cache_key *k;
    StoreEntry *e;
    ASState *asState = xcalloc(1, sizeof(ASState));
    cbdataAdd(asState);
    debug(53, 3) ("asnCacheStart: AS %d\n", as);
    snprintf(asres, 4096, "whois://%s/!gAS%d", Config.as_whois_server, as);
    k = storeKeyPublic(asres, METHOD_GET);
    asState->as_number = as;
    asState->request = urlParse(METHOD_GET, asres);
    if ((e = storeGet(k)) == NULL) {
	e = storeCreateEntry(asres, asres, 0, METHOD_GET);
	storeClientListAdd(e, asState);
	protoDispatch(0, e, asState->request);
    } else {
	storeLockObject(e);
	storeClientListAdd(e, asState);
    }
    asState->entry = e;
    storeClientCopy(e, 0, 0, 4096, get_free_4k_page(), asHandleReply, asState);
}

static void
asHandleReply(void *data, char *buf, ssize_t size)
{

    ASState *asState = data;
    StoreEntry *e = asState->entry;
    char *s;
    char *t;
    debug(50, 3) ("asHandleReply: Called with size=%d.\n", size);
    if (e->store_status == STORE_ABORTED) {
	put_free_4k_page(buf);
	return;
    }
    if (size == 0) {
	put_free_4k_page(buf);
	return;
    } else if (size < 0) {
	put_free_4k_page(buf);
	return;
    }
    if (e->store_status == STORE_PENDING) {
	storeClientCopy(e,
	    size,
	    0,
	    SM_PAGE_SIZE,
	    buf,
	    asHandleReply,
	    asState);
	return;
    }
/* XXX do the processing here */
    s = buf;
    while (*s) {
	for (t = s; *t; t++) {
	    if (isspace(*t))
		break;
	}
	if (*t == '\0') {
	    /* oof, word should continue on next block */
	    break;
	}
	*t = '\0';
	debug(53, 4) ("asHandleReply: AS# %s (%d) '\n", s, asState->as_number);
	asnAddNet(s, asState->as_number);
	s = t + 1;
	while (*s && isspace(*s))
	    s++;
    }
	/* XXX why assert that ? */
#if 0
    assert(e->mem_obj->reply);
#endif
    storeUnregister(e, asState);
    storeUnlockObject(e);
    requestUnlink(asState->request);
    cbdataFree(asState);
}


/* add a network (addr, mask) to the radix tree, with matching AS
 * number */

static int
asnAddNet(char *as_string, int as_number)
{
    rtentry *e = xmalloc(sizeof(rtentry));
    struct radix_node *rn;
    char dbg1[32], dbg2[32];
    intlist **Tail = NULL;
    intlist *q = NULL;
    as_info *as_info = NULL;
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
    mask = (1 << bitl) - 1;

    in_a.s_addr = addr;
    in_m.s_addr = mask;
    strcpy(dbg1, inet_ntoa(in_a));
    strcpy(dbg2, inet_ntoa(in_m));
    addr = ntohl(addr);
    mask = ntohl(mask);
    debug(53, 3) ("asnAddNet: called for %s/%s (%x/%x)\n", dbg1, dbg2, addr, mask);
    memset(e, '\0', sizeof(rtentry));
    store_m_int(addr, e->e_addr);
    store_m_int(mask, e->e_mask);
    rn = rn_lookup(e->e_addr, e->e_mask, AS_tree_head);
    if (rn != 0) {
	debug(53, 3) ("asnAddNet: warning: Found a network with multiple AS numbers!\n");
	as_info = ((rtentry *) rn)->e_info;
	for (Tail = &(as_info->as_number); *Tail; Tail = &((*Tail)->next));
	q = xcalloc(1, sizeof(intlist));
	q->i = as_number;
	*(Tail) = q;
	e->e_info = as_info;
    } else {
	q = xcalloc(1, sizeof(intlist));
	q->i = as_number;
	/* *(Tail) = q;         */
	as_info = xmalloc(sizeof(as_info));
	as_info->as_number = q;
	rn = rn_addroute(e->e_addr, e->e_mask, AS_tree_head, e->e_nodes);
	rn = rn_match(e->e_addr, AS_tree_head);
	assert(rn != NULL);
	e->e_info = as_info;
    }
    if (rn == 0) {
	xfree(e);
	debug(53, 3) ("asnAddNet: Could not add entry.\n");
	return 0;
    }
    e->e_info = as_info;
    debug(53, 3) ("asnAddNet: added successfully.\n");
    return 1;
}

static int
destroyRadixNode(struct radix_node *rn, void *w)
{
    struct radix_node_head *rnh = (struct radix_node_head *) w;

    if (rn && !(rn->rn_flags & RNF_ROOT)) {
	rtentry *e = (rtentry *) rn;
	rn = rn_delete(rn->rn_key, rn->rn_mask, rnh);
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
    intlist *first, *prev;
    intlist *data = e_info->as_number;
    first = data;
    prev = NULL;
    while (data) {
	prev = data;
	data = data->next;
	xfree(prev);
    }
    xfree(data);
}


void
whoisStart(request_t * request, StoreEntry * entry)
{
    int fd;
    whoisState *p = xcalloc(1, sizeof(whoisState));
    p->request = request;
    p->entry = entry;
    cbdataAdd(p);
    storeLockObject(p->entry);

    fd = comm_open(SOCK_STREAM, 0, any_addr, 0, COMM_NONBLOCKING, "whois");
    if (fd == COMM_ERROR) {
	debug(53, 0) ("whoisStart: failed to open a socket\n");
	return;
    }
    comm_add_close_handler(fd, whoisClose, p);
    commConnectStart(fd, request->host, request->port, whoisConnectDone, p);
}

static void
whoisConnectDone(int fd, int status, void *data)
{
    whoisState *p = data;
    char buf[128];
    if (status != COMM_OK) {
	debug(53, 0) ("whoisConnectDone: connection failed\n");
	comm_close(fd);
	return;
    }
    snprintf(buf, 128, "%s\r\n", p->request->urlpath + 1);
    debug(53, 1) ("whoisConnectDone: FD %d, '%s'\n", fd, p->request->urlpath + 1);
    comm_write(fd, xstrdup(buf), strlen(buf), NULL, p, xfree);
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
}

static void
whoisReadReply(int fd, void *data)
{
    whoisState *p = data;
    StoreEntry *entry = p->entry;
    char *buf = get_free_4k_page();
    int len;

    len = read(fd, buf, 4096);
    debug(53, 6) ("whoisReadReply: FD %d read %d bytes\n", fd, len);
    if (len <= 0) {
	storeComplete(entry);
	comm_close(fd);
	return;
    }
    storeAppend(entry, buf, len);
    fd_bytes(fd, len, FD_READ);
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
}

static void
whoisClose(int fd, void *data)
{
    whoisState *p = data;
    debug(53, 6) ("whoisClose: FD %d\n", fd);
    storeUnlockObject(p->entry);
    cbdataFree(p);
}
