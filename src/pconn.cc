
#include "squid.h"

#define PCONN_MAX_FDS 10

struct _pconn {
    char *key;
    struct _pconn *next;
    int fds[PCONN_MAX_FDS];
    int nfds;
};

static PF pconnRead;
static PF pconnTimeout;
static char *pconnKey _PARAMS((const char *host, u_short port));
static hash_table *table = NULL;
static struct _pconn *pconnNew _PARAMS((const char *key));
static void pconnDelete _PARAMS((struct _pconn * p));
static void pconnRemoveFD _PARAMS((struct _pconn * p, int fd));


static char *
pconnKey(const char *host, u_short port)
{
    LOCAL_ARRAY(char, buf, SQUIDHOSTNAMELEN + 10);
    snprintf(buf, SQUIDHOSTNAMELEN + 10, "%s.%d", host, (int) port);
    return buf;
}

static struct _pconn *
pconnNew(const char *key)
{
    struct _pconn *p = xcalloc(1, sizeof(struct _pconn));
    p->key = xstrdup(key);
    debug(0, 0) ("pconnNew: adding %s\n", p->key);
    hash_join(table, (hash_link *) p);
    return p;
}

static void
pconnDelete(struct _pconn *p)
{
    hash_link *hptr = hash_lookup(table, p->key);
    assert(hptr != NULL);
    debug(0, 0) ("pconnDelete: deleting %s\n", p->key);
    hash_remove_link(table, hptr);
}

static void
pconnRemoveFD(struct _pconn *p, int fd)
{
    int i;
    for (i = 0; i < p->nfds; i++) {
	if (p->fds[i] == fd)
	    break;
    }
    assert(i < p->nfds);
    debug(0, 0) ("pconnRemoveFD: found FD %d at index %d\n", fd, i);
    for (; i < p->nfds - 1; i++)
	p->fds[i] = p->fds[i + 1];
    if (--p->nfds == 0)
	pconnDelete(p);
}

static void
pconnTimeout(int fd, void *data)
{
    struct _pconn *p = data;
    assert(table != NULL);
    debug(0, 0) ("pconnTimeout: FD %d %s\n", fd, p->key);
    pconnRemoveFD(p, fd);
    comm_close(fd);
}

static void
pconnRead(int fd, void *data)
{
    LOCAL_ARRAY(char, buf, 256);
    struct _pconn *p = data;
    int n;
    assert(table != NULL);
    n = read(fd, buf, 256);
    debug(0, 0) ("pconnRead: %d bytes from FD %d, %s\n", n, fd, p->key);
    pconnRemoveFD(p, fd);
    comm_close(fd);
}


/* ========== PUBLIC FUNCTIONS ============================================ */


void
pconnInit(void)
{
    assert(table == NULL);
    table = hash_create((HASHCMP *) strcmp, 229, hash_string);
    debug(0, 0) ("persistent connection module initialized\n");
}

void
pconnPush(int fd, const char *host, u_short port)
{
    struct _pconn *p;
    char *key = xstrdup(pconnKey(host, port));
    assert(table != NULL);
    p = (struct _pconn *) hash_lookup(table, key);
    if (p == NULL)
	p = pconnNew(key);
    if (p->nfds == PCONN_MAX_FDS) {
	debug(0, 0) ("pconnPush: %s already has %d unused connections\n",
	    key, p->nfds);
	close(fd);
	xfree(key);
	return;
    }
    p->fds[p->nfds++] = fd;
    commSetSelect(fd, COMM_SELECT_READ, pconnRead, p, 0);
    commSetTimeout(fd, Config.Timeout.pconn, pconnTimeout, p);
    debug(0, 0) ("pconnPush: pushed FD %d for %s\n", fd, key);
}

int
pconnPop(const char *host, u_short port)
{
    struct _pconn *p;
    hash_link *hptr;
    int fd = -1;
    char *key = xstrdup(pconnKey(host, port));
    assert(table != NULL);
    hptr = hash_lookup(table, key);
    if (hptr != NULL) {
	p = (struct _pconn *) hptr;
	assert(p->nfds > 0);
	fd = p->fds[0];
	pconnRemoveFD(p, fd);
    }
    xfree(key);
    return fd;
}
