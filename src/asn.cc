
#include "squid.h"

#define WHOIS_PORT 43

static void asnLoadStart(int as);
static PF asnLoadClose;
static CNCB asnLoadConnected;
static PF asnLoadRead;

struct _asnLoadData {
    int as;
    char *buf;
    size_t bufsz;
    off_t offset;
};

/* PUBLIC */

int
asnMatchIp(void *data, struct in_addr addr)
{
    return 0;
}

void
asnAclInitialize(acl * acls)
{
    acl *a;
    intlist *i;
    debug(0, 0) ("asnAclInitialize: STARTING\n");
    for (a = acls; a; a = a->next) {
	if (a->type != ACL_DST_ASN && a->type != ACL_SRC_ASN)
	    continue;
	for (i = a->data; i; i = i->next) {
	    asnLoadStart(i->i);
	}
    }
}

/* PRIVATE */

static void
asnLoadStart(int as)
{
    int fd;
    struct _asnLoadData *p = xcalloc(1, sizeof(struct _asnLoadData));
    cbdataAdd(p);
    debug(0, 0) ("asnLoad: AS# %d\n", as);
    p->as = as;
    fd = comm_open(SOCK_STREAM, 0, any_addr, 0, COMM_NONBLOCKING, "asnLoad");
    if (fd == COMM_ERROR) {
	debug(0, 0) ("asnLoad: failed to open a socket\n");
	return;
    }
    comm_add_close_handler(fd, asnLoadClose, p);
    commConnectStart(fd, "whois.ra.net", WHOIS_PORT, asnLoadConnected, p);
}

static void
asnLoadClose(int fdnotused, void *data)
{
    struct _asnLoadData *p = data;
    cbdataFree(p);
}

static void
asnLoadConnected(int fd, int status, void *data)
{
    struct _asnLoadData *p = data;
    char buf[128];
    if (status != COMM_OK) {
	debug(0, 0) ("asnLoadConnected: connection failed\n");
	comm_close(fd);
	return;
    }
    snprintf(buf, 128, "!gAS%d\n", p->as);
    p->offset = 0;
    p->bufsz = 4096;
    p->buf = get_free_4k_page();
    debug(0, 0) ("asnLoadConnected: FD %d, '%s'\n", fd, buf);
    comm_write(fd, xstrdup(buf), strlen(buf), NULL, p, xfree);
    commSetSelect(fd, COMM_SELECT_READ, asnLoadRead, p, Config.Timeout.read);
}

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
    debug(0, 0) ("asnLoadRead: offset = %d\n", p->offset);
    s = p->buf + p->offset;
    len = read(fd, s, readsz);
    debug(0, 0) ("asnLoadRead: read %d bytes\n", len);
    if (len <= 0) {
	debug(0, 0) ("asnLoadRead: got EOF\n");
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
	debug(0, 0) ("asnLoadRead: AS# %d '%s'\n", p->as, s);
	s = t + 1;
	while (*s && isspace(*s))
	    s++;
    }
    if (*s) {
	/* expect more */
	debug(0, 0) ("asnLoadRead: AS# %d expecting more\n", p->as);
	xstrncpy(p->buf, s, p->bufsz);
	p->offset = strlen(p->buf);
	debug(0, 0) ("asnLoadRead: p->buf = '%s'\n", p->buf);
    } else {
	p->offset = 0;
    }
    commSetSelect(fd, COMM_SELECT_READ, asnLoadRead, p, Config.Timeout.read);
}
