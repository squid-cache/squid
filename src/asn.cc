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

#ifdef ASN_DIRECT
/* passed to asnLoadStart when reading configuration options */
struct _asnLoadData {
    int as;
    char *buf;
    size_t bufsz;
    off_t offset;
};

#endif

struct _whoisState {
    char *buf;
    StoreEntry *entry;
    request_t *request;
    size_t bufsz;
    off_t offset;
};

/* structure for as number information. it could be simply 
 * an intlist but it's coded as a structure for future
 * enhancements (e.g. expires)                                  */
struct _as_info {
    intlist *as_number;
    int expires;
};

struct _ASState {
    StoreEntry *entry;
    StoreEntry *asres_e;
    request_t *request;
    int flags;
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

static int asndbAddNet(char *, int);
#ifdef ASN_DIRECT
static CNCB asnLoadConnected;
static PF asnLoadRead;
static void asnLoadStart(int as);
static PF asnLoadClose;
#endif
static void asnCacheStart(int as);
static PF whoisClose;
static CNCB whoisConnectDone;
static PF whoisReadReply;
static STCB asHandleReply;

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
    intlist *a = NULL, *b = NULL;
    lh = ntohl(addr.s_addr);
    debug(53, 4) ("asnMatchIp: Called for %s.\n", inet_ntoa(addr));

    if (AS_tree_head == 0)
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
	for (i = a->data; i; i = i->next) {
#ifdef ASN_DIRECT
	    asnLoadStart(i->i);
#else
	    asnCacheStart(i->i);
#endif
	}
    }
}

/* PRIVATE */


static void
asnCacheStart(int as)
{
    LOCAL_ARRAY(char, asres, 4096);
    const cache_key *k;
    StoreEntry *asres_e;
    ASState *asState;
    request_t *asres_r;
    snprintf(asres, 4096, "whois://%s/!gAS%d", Config.as_whois_server, as);
    k = storeKeyPublic(asres, METHOD_GET);
    asState = xcalloc(1, sizeof(asState));
    cbdataAdd(asState);
    asres_r = urlParse(METHOD_GET, asres);
    asState->as_number = as;
    asState->request = asres_r;

    if ((asres_e = storeGet(k)) == NULL) {
	asres_e = storeCreateEntry(asres, asres, 0, METHOD_GET);
	asState->asres_e = asres_e;
	storeClientListAdd(asres_e, asState);
	protoDispatch(0, asres_e, asres_r);
    } else {
	storeLockObject(asres_e);
	asState->asres_e = asres_e;
	storeClientListAdd(asres_e, asState);
    }
    storeClientCopy(asres_e,
	0,
	0,
	4096,
	get_free_4k_page(),
	asHandleReply,
	asState);
}

static void
asHandleReply(void *data, char *buf, ssize_t size)
{

    ASState *asState = data;
    StoreEntry *asres_e = asState->asres_e;
    char *s, *t;

    debug(50, 3) ("asHandleReply: Called with size=%d.\n", size);
    if (asres_e->store_status == STORE_ABORTED) {
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
    if (asres_e->store_status == STORE_PENDING) {
	storeClientCopy(asres_e,
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
	asndbAddNet(s, asState->as_number);
	s = t + 1;
	while (*s && isspace(*s))
	    s++;
    }

    assert(asres_e->mem_obj->reply);
    storeUnregister(asres_e, asState);
    storeUnlockObject(asres_e);
    requestUnlink(asState->request);
/* XXX this dumps core, don't know why */
#if 0
    cbdataFree(asState);
#endif
}


#ifdef ASN_DIRECT

/* connects to whois server to find out networks belonging to 
 * a certain AS */

static void
asnLoadStart(int as)
{
    int fd;
    struct _asnLoadData *p = xcalloc(1, sizeof(struct _asnLoadData));
    cbdataAdd(p);
    debug(53, 1) ("asnLoadStart: AS# %d\n", as);
    p->as = as;
    fd = comm_open(SOCK_STREAM, 0, any_addr, 0, COMM_NONBLOCKING, "asnLoad");
    if (fd == COMM_ERROR) {
	debug(53, 0) ("asnLoadStart: failed to open a socket\n");
	return;
    }
    comm_add_close_handler(fd, asnLoadClose, p);
    commConnectStart(fd, Config.as_whois_server, WHOIS_PORT, asnLoadConnected, p);
}


/* we're finished, so we close the connection and add the
 * network numbers to the database */

static void
asnLoadClose(int fdnotused, void *data)
{
    struct _asnLoadData *p = data;
    debug(53, 6) ("asnLoadClose: called\n");
    cbdataFree(p);
}


/* we're connected to the whois server, so we send out the request ! */
static void
asnLoadConnected(int fd, int status, void *data)
{
    struct _asnLoadData *p = data;
    char buf[128];
    if (status != COMM_OK) {
	debug(53, 0) ("asnLoadConnected: connection failed\n");
	comm_close(fd);
	return;
    }
    snprintf(buf, 128, "!gAS%d\n", p->as);
    p->offset = 0;
    p->bufsz = 4096;
    p->buf = get_free_4k_page();
    debug(53, 1) ("asnLoadConnected: FD %d, '%s'\n", fd, buf);
    comm_write(fd, xstrdup(buf), strlen(buf), NULL, p, xfree);
    commSetSelect(fd, COMM_SELECT_READ, asnLoadRead, p, Config.Timeout.read);
}

/* we got reply data waiting, copy it to our buffer structure 
 * to parse it later */

static void
asnLoadRead(int fd, void *data)
{
    struct _asnLoadData *p = data;
    char *t;
    char *s;
    size_t readsz;
    int len;

    readsz = p->bufsz - p->offset;
    readsz--;
    debug(53, 6) ("asnLoadRead: offset = %d\n", p->offset);
    s = p->buf + p->offset;
    len = read(fd, s, readsz);
    debug(53, 6) ("asnLoadRead: read %d bytes\n", len);
    if (len <= 0) {
	debug(53, 5) ("asnLoadRead: got EOF\n");
	comm_close(fd);
	return;
    }
    fd_bytes(fd, len, FD_READ);
    p->offset += len;
    *(s + len) = '\0';
    s = p->buf;
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
	debug(53, 4) ("asnLoadRead: AS# %d '%s'\n", p->as, s);
	asndbAddNet(s, p->as);
	s = t + 1;
	while (*s && isspace(*s))
	    s++;
    }
    if (*s) {
	/* expect more */
	debug(53, 6) ("asnLoadRead: AS# %d expecting more\n", p->as);
	xstrncpy(p->buf, s, p->bufsz);
	p->offset = strlen(p->buf);
	debug(53, 6) ("asnLoadRead: p->buf = '%s'\n", p->buf);
    } else {
	p->offset = 0;
    }
    commSetSelect(fd, COMM_SELECT_READ, asnLoadRead, p, Config.Timeout.read);
}

#endif

/* initialize the radix tree structure */

void
asndbInit()
{
    extern int max_keylen;
    max_keylen = 40;
    rn_init();
    rn_inithead((void **) &AS_tree_head, 8);

}

/* add a network (addr, mask) to the radix tree, with matching AS
 * number */

static int
asndbAddNet(char *as_string, int as_number)
{
    rtentry *e = xmalloc(sizeof(rtentry));
    struct radix_node *rn;
    char dbg1[32], dbg2[32];
    intlist **Tail = NULL;
    intlist *q = NULL;
    as_info *info = NULL;
    struct in_addr in_a, in_m;
    long mask, addr;
    char *t;
    int bitl;

    t = index(as_string, '/');
    if (t == NULL) {
	debug(53, 3) ("asndbAddNet: failed, invalid response from whois server.\n");
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
    debug(53, 3) ("asndbAddNet: called for %s/%s (%x/%x)\n", dbg1, dbg2, addr, mask);
    memset(e, '\0', sizeof(rtentry));
    store_m_int(addr, e->e_addr);
    store_m_int(mask, e->e_mask);
    rn = rn_lookup(e->e_addr, e->e_mask, AS_tree_head);
    if (rn != 0) {
	debug(53, 3) ("asndbAddNet: warning: Found a network with multiple AS numbers!\n");
	info = ((rtentry *) rn)->e_info;
	for (Tail = &(info->as_number); *Tail; Tail = &((*Tail)->next));
	q = xcalloc(1, sizeof(intlist));
	q->i = as_number;
	*(Tail) = q;
	e->e_info = info;
    } else {
	q = xcalloc(1, sizeof(intlist));
	q->i = as_number;
	/* *(Tail) = q;         */
	info = xmalloc(sizeof(as_info));
	info->as_number = q;
	rn = rn_addroute(e->e_addr, e->e_mask, AS_tree_head, e->e_nodes);
	rn = rn_match(e->e_addr, AS_tree_head);
	if (rn == NULL)
	    fatal_dump("cannot add entry...\n");
	e->e_info = info;

    }
    if (rn == 0) {
	xfree(e);
	debug(53, 3) ("asndbAddNet: Could not add entry.\n");
	return 0;
    }
    e->e_info = info;
    debug(53, 3) ("asndbAddNet: added successfully.\n");
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

void
asnCleanup()
{
    rn_walktree(AS_tree_head, destroyRadixNode, AS_tree_head);
    destroyRadixNode((struct radix_node *) 0, (void *) AS_tree_head);
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
    p->offset = 0;
    p->bufsz = 4096;
    p->buf = get_free_4k_page();
    debug(53, 1) ("whoisConnectDone: FD %d, '%s'\n", fd, p->request->urlpath + 1);
    comm_write(fd, xstrdup(buf), strlen(buf), NULL, p, xfree);
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
}

static void
whoisReadReply(int fd, void *data)
{
    whoisState *p = data;
    StoreEntry *entry = p->entry;
    char *s;
    size_t readsz;
    int len;

    readsz = p->bufsz - p->offset;
    readsz--;
    debug(53, 6) ("whoisReadReply: offset = %d\n", p->offset);
    s = p->buf + p->offset;
    len = read(fd, s, readsz);
    debug(53, 6) ("whoisReadReply: read %d bytes\n", len);
    if (len <= 0) {
	debug(53, 5) ("whoisReadReply: got EOF (%s)\n", p->buf);
	comm_close(fd);
	return;
    }
    storeAppend(entry, s, len);
    fd_bytes(fd, len, FD_READ);
    p->offset += len;
    *(s + len) = '\0';
    if (*s) {
	/* expect more */
	debug(53, 6) ("whoisReadReply: expecting more\n");
	xstrncpy(p->buf, s, p->bufsz);
	p->offset = strlen(p->buf);
	debug(53, 6) ("whoisReadReply: p->buf = '%s'\n", p->buf);
    } else {
	p->offset = 0;
    }
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
}

static void
whoisClose(int fdnotused, void *data)
{
    whoisState *p = data;
    StoreEntry *entry = p->entry;
    debug(53, 6) ("whoisClose called\n");
    storeComplete(entry);
    /* XXX free up whoisState */
    cbdataFree(p);
}
