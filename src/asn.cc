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

static int asndbAddNet(char *, int);
static void asnLoadStart(int as);
static PF asnLoadClose;
static CNCB asnLoadConnected;
static PF asnLoadRead;
extern struct radix_node *rn_lookup(void *, void *, void *);
/* Head for ip to asn radix tree */
struct radix_node_head *AS_tree_head;

/* passed to asnLoadStart when reading configuration options */
struct _asnLoadData {
    int as;
    char *buf;
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
typedef struct _as_info as_info;

/* entry into the radix tree */
struct _rtentry {
    struct radix_node e_nodes[2];
    as_info *e_info;
    m_int e_addr;
    m_int e_mask;
};

typedef struct _rtentry rtentry;



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
	    asnLoadStart(i->i);
	}
    }
}

/* PRIVATE */


/* connects to whois server to find out networks belonging to 
 * a certain AS */

static void
asnLoadStart(int as)
{
    int fd;
    struct _asnLoadData *p = xcalloc(1, sizeof(struct _asnLoadData));
    cbdataAdd(p);
    debug(53, 1) ("asnLoad: AS# %d\n", as);
    p->as = as;
    fd = comm_open(SOCK_STREAM, 0, any_addr, 0, COMM_NONBLOCKING, "asnLoad");
    if (fd == COMM_ERROR) {
	debug(53, 0) ("asnLoad: failed to open a socket\n");
	return;
    }
    comm_add_close_handler(fd, asnLoadClose, p);
    commConnectStart(fd, "whois.ra.net", WHOIS_PORT, asnLoadConnected, p);
}


/* we're finished, so we close the connection and add the
 * network numbers to the database */

static void
asnLoadClose(int fdnotused, void *data)
{
    struct _asnLoadData *p = data;
    debug(53, 6) ("asnLoadClose called\n");
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
	debug(53, 3) ("asndbAddNet: failed, no network.\n");
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
	debug(53, 3) ("Oops. Found a network with multiple AS numbers!\n");
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
	debug(53, 3) ("Could not add entry.\n");
	return 0;
    }
    e->e_info = info;
    debug(53, 3) ("added successfully.\n");
    return 1;
}
