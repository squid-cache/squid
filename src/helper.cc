#include "squid.h"

#define HELPER_MAX_ARGS 64

static PF helperHandleRead;
static PF helperServerFree;
static void Enqueue(helper * hlp, helper_request *);
static helper_request *Dequeue(helper * hlp);
static helper_server *GetFirstAvailable(helper * hlp);
static void helperDispatch(helper_server * srv, helper_request * r);
static void helperKickQueue(helper * hlp);
static void helperRequestFree(helper_request * r);


void
helperOpenServers(helper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    char *args[HELPER_MAX_ARGS];
    char fd_note_buf[FD_DESC_SZ];
    helper_server *srv;
    int nargs = 0;
    int k;
    int x;
    int rfd;
    int wfd;
    wordlist *w;
    if (hlp->cmdline == NULL)
	return;
    progname = hlp->cmdline->key;
    if ((s = strrchr(progname, '/')))
	shortname = xstrdup(s + 1);
    else
	shortname = xstrdup(progname);
    debug(29, 1) ("helperOpenServers: Starting %d '%s' processes\n",
	hlp->n_to_start, shortname);
    procname = xmalloc(strlen(shortname) + 3);
    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);
    args[nargs++] = procname;
    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
	args[nargs++] = w->key;
    args[nargs++] = NULL;
    assert(nargs <= HELPER_MAX_ARGS);
    for (k = 0; k < hlp->n_to_start; k++) {
	getCurrentTime();
	rfd = wfd = -1;
	x = ipcCreate(hlp->ipc_type,
	    progname,
	    args,
	    shortname,
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(29, 1) ("WARNING: Cannot run '%s' process.\n", progname);
	    continue;
	}
	hlp->n_running++;
	srv = memAllocate(MEM_HELPER_SERVER);
	cbdataAdd(srv, memFree, MEM_HELPER_SERVER);
	srv->flags.alive = 1;
	srv->index = k;
	srv->rfd = rfd;
	srv->wfd = wfd;
	srv->buf = memAllocate(MEM_8K_BUF);
	srv->buf_sz = 8192;
	srv->offset = 0;
	srv->parent = hlp;
	cbdataLock(hlp);	/* lock because of the parent backlink */
	dlinkAddTail(srv, &srv->link, &hlp->servers);
	if (rfd == wfd) {
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	} else {
	    snprintf(fd_note_buf, FD_DESC_SZ, "reading %s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	    snprintf(fd_note_buf, FD_DESC_SZ, "writing %s #%d", shortname, k + 1);
	    fd_note(wfd, fd_note_buf);
	}
	commSetNonBlocking(rfd);
	if (wfd != rfd)
	    commSetNonBlocking(wfd);
	comm_add_close_handler(rfd, helperServerFree, srv);
    }
    safe_free(shortname);
    safe_free(procname);
    helperKickQueue(hlp);
}

void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    helper_request *r = memAllocate(MEM_HELPER_REQUEST);
    helper_server *srv;
    if (hlp == NULL) {
	debug(29, 3) ("helperSubmit: hlp == NULL\n");
	callback(data, NULL);
	return;
    }
    r->callback = callback;
    r->data = data;
    r->buf = xstrdup(buf);
    cbdataLock(r->data);
    if ((srv = GetFirstAvailable(hlp)))
	helperDispatch(srv, r);
    else
	Enqueue(hlp, r);
}

void
helperStats(StoreEntry * sentry, helper * hlp)
{
    helper_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "number running: %d of %d\n",
	hlp->n_running, hlp->n_to_start);
    storeAppendPrintf(sentry, "requests sent: %d\n",
	hlp->stats.requests);
    storeAppendPrintf(sentry, "replies received: %d\n",
	hlp->stats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	hlp->stats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %d msec\n",
	hlp->stats.avg_svc_time);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%11s\t%s\t%7s\t%7s\n",
	"#",
	"FD",
	"# Requests",
	"Flags",
	"Time",
	"Offset");
    for (link = hlp->servers.head; link; link = link->next) {
	srv = link->data;
	tt = 0.001 * tvSubMsec(srv->dispatch_time, current_time);
	storeAppendPrintf(sentry, "%7d\t%7d\t%11d\t%c%c%c%c\t%7.3f\t%7d\n",
	    srv->index + 1,
	    srv->rfd,
	    srv->stats.uses,
	    srv->flags.alive ? 'A' : ' ',
	    srv->flags.busy ? 'B' : ' ',
	    srv->flags.closing ? 'C' : ' ',
	    srv->flags.shutdown ? 'S' : ' ',
	    tt < 0.0 ? 0.0 : tt,
	    (int) srv->offset);
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
}

void
helperShutdown(helper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_server *srv;
    while (link) {
	srv = link->data;
	link = link->next;
	if (!srv->flags.alive) {
	    debug(34, 3) ("helperShutdown: %s #%d is NOT ALIVE.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.shutdown = 1;	/* request it to shut itself down */
	if (srv->flags.busy) {
	    debug(34, 3) ("helperShutdown: %s #%d is BUSY.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.closing) {
	    debug(34, 3) ("helperShutdown: %s #%d is CLOSING.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.closing = 1;
	comm_close(srv->rfd);
    }
}

helper *
helperCreate(const char *name)
{
    helper *hlp = memAllocate(MEM_HELPER);
    cbdataAdd(hlp, memFree, MEM_HELPER);
    hlp->id_name = name;
    return hlp;
}

void
helperFree(helper * hlp)
{
    /* note, don't free hlp->name, it probably points to static memory */
    if (hlp->queue.head)
	debug(29, 0) ("WARNING: freeing %s helper with %d requests queued\n",
	    hlp->id_name, hlp->stats.queue_size);
    cbdataFree(hlp);
}

/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static void
helperServerFree(int fd, void *data)
{
    helper_server *srv = data;
    helper *hlp = srv->parent;
    helper_request *r;
    assert(srv->rfd == fd);
    if (srv->buf) {
	memFree(srv->buf, MEM_8K_BUF);
	srv->buf = NULL;
    }
    if ((r = srv->request)) {
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	helperRequestFree(r);
	srv->request = NULL;
    }
    if (srv->wfd != srv->rfd)
	comm_close(srv->wfd);
    dlinkDelete(&srv->link, &hlp->servers);
    hlp->n_running--;
    assert(hlp->n_running >= 0);
    if (!srv->flags.shutdown) {
	debug(34, 0) ("WARNING: %s #%d (FD %d) exited\n",
	    hlp->id_name, srv->index + 1, fd);
	if (hlp->n_running < hlp->n_to_start / 2)
	    fatalf("Too few %s processes are running", hlp->id_name);
    }
    cbdataUnlock(srv->parent);
    cbdataFree(srv);
}

static void
helperHandleRead(int fd, void *data)
{
    int len;
    char *t = NULL;
    helper_server *srv = data;
    helper_request *r;
    helper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataValid(data));
    Counter.syscalls.sock.reads++;
    len = read(fd, srv->buf + srv->offset, srv->buf_sz - srv->offset);
    fd_bytes(fd, len, FD_READ);
    debug(29, 5) ("helperHandleRead: %d bytes from %s #%d.\n",
	len, hlp->id_name, srv->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(50, 1) ("helperHandleRead: FD %d read: %s\n", fd, xstrerror());
	comm_close(fd);
	return;
    }
    srv->offset += len;
    srv->buf[srv->offset] = '\0';
    r = srv->request;
    if (r == NULL) {
	/* someone spoke without being spoken to */
	debug(29, 1) ("helperHandleRead: unexpected read from %s #%d, %d bytes\n",
	    hlp->id_name, srv->index + 1, len);
	srv->offset = 0;
    } else if ((t = strchr(srv->buf, '\n'))) {
	/* end of reply found */
	debug(29, 3) ("helperHandleRead: end of reply found\n");
	*t = '\0';
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	srv->flags.busy = 0;
	srv->offset = 0;
	helperRequestFree(r);
	srv->request = NULL;
	hlp->stats.replies++;
	hlp->stats.avg_svc_time =
	    intAverage(hlp->stats.avg_svc_time,
	    tvSubMsec(srv->dispatch_time, current_time),
	    hlp->stats.replies, REDIRECT_AV_FACTOR);
	if (srv->flags.shutdown)
	    comm_close(srv->wfd);
	else
	    helperKickQueue(hlp);
    } else {
	commSetSelect(srv->rfd, COMM_SELECT_READ, helperHandleRead, srv, 0);
    }
}

static void
Enqueue(helper * hlp, helper_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;
    if (hlp->stats.queue_size < hlp->n_running)
	return;
    if (squid_curtime - hlp->last_queue_warn < 600)
	return;
    if (shutting_down || reconfiguring)
	return;
    hlp->last_queue_warn = squid_curtime;
    debug(14, 0) ("WARNING: All %s processes are busy.\n", hlp->id_name);
    debug(14, 0) ("WARNING: %d pending requests queued\n", hlp->stats.queue_size);
    if (hlp->stats.queue_size > hlp->n_running * 2)
	fatalf("Too many queued %s requests", hlp->id_name);
    debug(14, 1) ("Consider increasing the number of %s processes in your config file.\n", hlp->id_name);
}

static helper_request *
Dequeue(helper * hlp)
{
    dlink_node *link;
    helper_request *r = NULL;
    if ((link = hlp->queue.head)) {
	r = link->data;
	dlinkDelete(link, &hlp->queue);
	memFree(link, MEM_DLINK_NODE);
	hlp->stats.queue_size--;
    }
    return r;
}

static helper_server *
GetFirstAvailable(helper * hlp)
{
    dlink_node *n;
    helper_server *srv = NULL;
    if (hlp->n_running == 0)
	return NULL;
    for (n = hlp->servers.head; n != NULL; n = n->next) {
	srv = n->data;
	if (srv->flags.busy)
	    continue;
	if (!srv->flags.alive)
	    continue;
	return srv;
    }
    return NULL;
}

static void
helperDispatch(helper_server * srv, helper_request * r)
{
    helper *hlp = srv->parent;
    if (!cbdataValid(r->data)) {
	debug(29, 1) ("helperDispatch: invalid callback data\n");
	helperRequestFree(r);
	return;
    }
    assert(!srv->flags.busy);
    srv->flags.busy = 1;
    srv->request = r;
    srv->dispatch_time = current_time;
    comm_write(srv->wfd,
	r->buf,
	strlen(r->buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	NULL);			/* free */
    commSetSelect(srv->rfd,
	COMM_SELECT_READ,
	helperHandleRead,
	srv, 0);
    debug(29, 5) ("helperDispatch: Request sent to %s #%d, %d bytes\n",
	hlp->id_name, srv->index + 1, strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}

static void
helperKickQueue(helper * hlp)
{
    helper_request *r;
    helper_server *srv;
    while ((srv = GetFirstAvailable(hlp)) && (r = Dequeue(hlp)))
	helperDispatch(srv, r);
}

static void
helperRequestFree(helper_request * r)
{
    cbdataUnlock(r->data);
    xfree(r->buf);
    memFree(r, MEM_HELPER_REQUEST);
}
