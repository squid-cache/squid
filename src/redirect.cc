/*
 * $Id: redirect.cc,v 1.2 1996/07/09 03:41:37 wessels Exp $
 *
 * DEBUG: section 29    Redirector
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#define REDIRECT_FLAG_ALIVE		0x01
#define REDIRECT_FLAG_BUSY		0x02
#define REDIRECT_FLAG_CLOSING	0x04

typedef void (*RH) _PARAMS((int, char *));


typedef struct {
    int fd;
    char *orig_url;
    RH handler;
} redirectStateData;

typedef struct _redirector {
    int index;
    int flags;
    int fd;
    char *inbuf;
    unsigned int size;
    unsigned int offset;
    redirectStateData *redirectState;
} redirector_t;

struct redirectQueueData {
    struct redirectQueueData *next;
    redirectStateData *redirectState;
};

static redirector_t *GetFirstAvailable _PARAMS((void));
static int redirectCreateRedirector _PARAMS((char *command));
static int redirectHandleRead _PARAMS((int, redirector_t *));
static redirectStateData *Dequeue _PARAMS(());
static void Enqueue _PARAMS((redirectStateData *));
static void redirectDispatch _PARAMS((redirector_t *, redirectStateData *));


static redirector_t **redirect_child_table = NULL;
static int NRedirectors = 0;
static struct redirectQueueData *redirectQueueHead = NULL;
static struct redirectQueueData **redirectQueueTailP = &redirectQueueHead;

/* TCP SOCKET VERSION */
int redirectCreateRedirector(command)
     char *command;
{
    int pid;
    u_short port;
    struct sockaddr_in S;
    static int n_redirector = 0;
    int cfd;
    int sfd;
    int len;
    int fd;
    cfd = comm_open(COMM_NOCLOEXEC,
	local_addr,
	0,
	"socket to redirector");
    if (cfd == COMM_ERROR) {
	debug(14, 0, "redirect_create_redirector: Failed to create redirector\n");
	return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
	debug(14, 0, "redirect_create_redirector: getsockname: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    port = ntohs(S.sin_port);
    debug(14, 4, "redirect_create_redirector: bind to local host.\n");
    listen(cfd, 1);
    if ((pid = fork()) < 0) {
	debug(14, 0, "redirect_create_redirector: fork: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    if (pid > 0) {		/* parent */
	comm_close(cfd);	/* close shared socket with child */
	/* open new socket for parent process */
	sfd = comm_open(0, local_addr, 0, NULL);	/* blocking! */
	if (sfd == COMM_ERROR)
	    return -1;
	if (comm_connect(sfd, localhost, port) == COMM_ERROR) {
	    comm_close(sfd);
	    return -1;
	}
	comm_set_fd_lifetime(sfd, -1);
	debug(14, 4, "redirect_create_redirector: FD %d connected to %s #%d.\n",
	    sfd, command, n_redirector);
	return sfd;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    dup2(cfd, 3);
    for (fd = FD_SETSIZE; fd > 3; fd--)
	close(fd);
    execlp(command, "(redirector)", "-t", NULL);
    debug(14, 0, "redirect_create_redirector: %s: %s\n", command, xstrerror());
    _exit(1);
    return 0;
}



int redirectHandleRead(fd, redirector)
     int fd;
     redirector_t *redirector;
{
    int len;
    redirectStateData *r = redirector->redirectState;
    char *t = NULL;

    len = read(fd,
	redirector->inbuf + redirector->offset,
	redirector->size - redirector->offset);
    debug(14, 5, "redirectHandleRead: Result from Redirector %d.\n",
	redirector->index + 1);
    if (len <= 0) {
	debug(14, redirector->flags & REDIRECT_FLAG_CLOSING ? 5 : 1,
	    "FD %d: Connection from Redirector #%d is closed, disabling\n",
	    fd, redirector->index + 1);
	redirector->flags = 0;
	comm_close(fd);
	return 0;
    }
    redirector->offset += len;
    redirector->inbuf[redirector->offset] = '\0';
    /* reschedule */
    comm_set_select_handler(redirector->fd,
	COMM_SELECT_READ,
	(PF) redirectHandleRead,
	redirector);
    if ((t = strchr(redirector->inbuf, '\n'))) {
	/* end of record found */
	*t = '\0';
	if (t == redirector->inbuf)
	    r->handler(r->fd, r->orig_url);
	else
	    r->handler(r->fd, redirector->inbuf);
	redirector->redirectState = NULL;
	redirector->flags &= ~REDIRECT_FLAG_BUSY;
    }
    while ((r = Dequeue()) && (redirector = GetFirstAvailable()))
	redirectDispatch(redirector, r);
    return 0;
}

void redirectStart(url, fd, handler)
     char *url;
     int fd;
     RH handler;
{
    redirectStateData *r = NULL;
    redirector_t *redirector = NULL;

    if (!handler)
	fatal_dump("redirectStart: NULL handler");
    r = xcalloc(1, sizeof(redirectStateData));
    r->fd = fd;
    r->orig_url = url;
    r->handler = handler;
    if ((redirector = GetFirstAvailable()))
	redirectDispatch(redirector, r);
    else
	Enqueue(r);
}

static void Enqueue(r)
     redirectStateData *r;
{
    struct redirectQueueData *new = xcalloc(1, sizeof(struct redirectQueueData));
    new->redirectState = r;
    *redirectQueueTailP = new;
    redirectQueueTailP = &new->next;
}

static redirectStateData *Dequeue()
{
    struct redirectQueueData *old = NULL;
    redirectStateData *r = NULL;
    if (redirectQueueHead) {
	r = redirectQueueHead->redirectState;
	old = redirectQueueHead;
	redirectQueueHead = redirectQueueHead->next;
	if (redirectQueueHead == NULL)
	    redirectQueueTailP = &redirectQueueHead;
	safe_free(old);
    }
    return r;
}

static redirector_t *GetFirstAvailable()
{
    int k;
    redirector_t *redirect = NULL;
    for (k = 0; k < NRedirectors; k++) {
	redirect = *(redirect_child_table + k);
	if (!(redirect->flags & REDIRECT_FLAG_BUSY))
	    return redirect;
    }
    return NULL;
}


static void redirectDispatch(redirect, r)
     redirector_t *redirect;
     redirectStateData *r;
{
    char *buf = NULL;
    redirect->flags |= REDIRECT_FLAG_BUSY;
    redirect->redirectState = r;
    comm_write(redirect->fd,
	xstrdup(buf),
	strlen(buf),
	0,			/* timeout */
	NULL,			/* Handler */
	NULL);			/* Handler-data */
    debug(14, 5, "redirectDispatch: Request sent to Redirector #%d.\n",
	redirect->index + 1);
}


void redirectOpenServers()
{
    char *prg = getRedirectProgram();
    int k;
    int redirectsocket;
    static char fd_note_buf[FD_ASCII_NOTE_SZ];

    /* free old structures if present */
    if (redirect_child_table) {
	for (k = 0; k < NRedirectors; k++)
	    safe_free(redirect_child_table[k]);
	safe_free(redirect_child_table);
    }
    NRedirectors = getRedirectChildren();
    redirect_child_table = xcalloc(NRedirectors, sizeof(redirector_t *));
    debug(14, 1, "redirectOpenServers: Starting %d '%s' processes\n",
	NRedirectors, prg);
    for (k = 0; k < NRedirectors; k++) {
	redirect_child_table[k] = xcalloc(1, sizeof(redirector_t));
	if ((redirectsocket = redirectCreateRedirector(prg)) < 0) {
	    debug(14, 1, "WARNING: Cannot run '%s' process.\n", prg);
	    redirect_child_table[k]->flags &= ~REDIRECT_FLAG_ALIVE;
	} else {
	    redirect_child_table[k]->flags |= REDIRECT_FLAG_ALIVE;
	    redirect_child_table[k]->index = k;
	    redirect_child_table[k]->fd = redirectsocket;
	    sprintf(fd_note_buf, "%s #%d",
		prg,
		redirect_child_table[k]->index + 1);
	    fd_note(redirect_child_table[k]->fd, fd_note_buf);
	    commSetNonBlocking(redirect_child_table[k]->fd);

	    /* set handler for incoming result */
	    comm_set_select_handler(redirect_child_table[k]->fd,
		COMM_SELECT_READ,
		(PF) redirectHandleRead,
		(void *) redirect_child_table[k]);
	    debug(14, 3, "redirectOpenServers: 'redirect_server' %d started\n",
		k);
	}
    }
}

int redirectUnregister(url, fd)
     char *url;
     int fd;
{
    return 0;
}

void redirectShutdownServers()
{
    redirector_t *redirector = NULL;
    int k;
    static char *shutdown = "$shutdown\n";

    debug(14, 3, "redirectShutdownServers:\n");

    for (k = 0; k < getRedirectChildren(); k++) {
	redirector = *(redirect_child_table + k);
	debug(14, 3, "redirectShutdownServers: sending '$shutdown' to redirector #%d\n", k);
	debug(14, 3, "redirectShutdownServers: --> FD %d\n", redirector->fd);
	comm_write(redirector->fd,
	    xstrdup(shutdown),
	    strlen(shutdown),
	    0,			/* timeout */
	    NULL,		/* Handler */
	    NULL);		/* Handler-data */
	redirector->flags |= REDIRECT_FLAG_CLOSING;
    }
}
