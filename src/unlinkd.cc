/*
 * $Id: unlinkd.cc,v 1.32 1999/10/04 05:05:38 wessels Exp $
 *
 * DEBUG: section 12    Unlink Daemon
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#ifdef UNLINK_DAEMON

/* This is the external unlinkd process */

#define UNLINK_BUF_LEN 1024

int
main(int argc, char *argv[])
{
    char buf[UNLINK_BUF_LEN];
    char *t;
    int x;
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    while (fgets(buf, UNLINK_BUF_LEN, stdin)) {
	if ((t = strchr(buf, '\n')))
	    *t = '\0';
#if USE_TRUNCATE
	x = truncate(buf, 0);
#else
	x = unlink(buf);
#endif
	if (x < 0)
	    printf("ERR\n");
	else
	    printf("OK\n");
    }
    exit(0);
}

#else /* UNLINK_DAEMON */

/* This code gets linked to Squid */

#if USE_UNLINKD
static int unlinkd_wfd = -1;
static int unlinkd_rfd = -1;
#endif

#define UNLINKD_QUEUE_LIMIT 20

void
unlinkdUnlink(const char *path)
{
#if USE_UNLINKD
    char buf[MAXPATHLEN];
    int l;
    int x;
    static int queuelen = 0;
    if (unlinkd_wfd < 0) {
	debug_trap("unlinkdUnlink: unlinkd_wfd < 0");
	safeunlink(path, 0);
	return;
    }
    /*
     * If the queue length is greater than our limit, then
     * we pause for up to 100ms, hoping that unlinkd
     * has some feedback for us.  Maybe it just needs a slice
     * of the CPU's time.
     */
    if (queuelen >= UNLINKD_QUEUE_LIMIT) {
	struct timeval to;
	fd_set R;
	int x;
	FD_ZERO(&R);
	FD_SET(unlinkd_rfd, &R);
	to.tv_sec = 0;
	to.tv_usec = 100000;
	x = select(unlinkd_rfd + 1, &R, NULL, NULL, &to);
    }
    /*
     * If there is at least one outstanding unlink request, then
     * try to read a response.  If there's nothing to read we'll
     * get an EWOULDBLOCK or whatever.  If we get a response, then
     * decrement the queue size by the number of newlines read.
     */
    if (queuelen > 0) {
	int x;
	int i;
	char rbuf[512];
	x = read(unlinkd_rfd, rbuf, 511);
	if (x > 0) {
	    rbuf[x] = '\0';
	    for (i = 0; i < x; i++)
		if ('\n' == rbuf[i])
		    queuelen--;
	    assert(queuelen >= 0);
	}
    }
    l = strlen(path);
    assert(l < MAXPATHLEN);
    xstrncpy(buf, path, MAXPATHLEN);
    buf[l++] = '\n';
    x = write(unlinkd_wfd, buf, l);
    if (x < 0) {
	debug(50, 1) ("unlinkdUnlink: write FD %d failed: %s\n",
	    unlinkd_wfd, xstrerror());
	safeunlink(path, 0);
	return;
    } else if (x != l) {
	debug(50, 1) ("unlinkdUnlink: FD %d only wrote %d of %d bytes\n",
	    unlinkd_wfd, x, l);
	safeunlink(path, 0);
	return;
    }
    Counter.unlink.requests++;
    queuelen++;
#endif
}

void
unlinkdClose(void)
{
#if USE_UNLINKD
    assert(unlinkd_wfd > -1);
    debug(12, 1) ("Closing unlinkd pipe on FD %d\n", unlinkd_wfd);
    file_close(unlinkd_wfd);
    if (unlinkd_wfd != unlinkd_rfd)
	file_close(unlinkd_rfd);
    unlinkd_wfd = -1;
    unlinkd_rfd = -1;
#endif
}

void
unlinkdInit(void)
{
#if USE_UNLINKD
    int x;
    char *args[2];
    struct timeval slp;
    args[0] = "(unlinkd)";
    args[1] = NULL;
#if HAVE_POLL && defined(_SQUID_OSF_)
    /* pipes and poll() don't get along on DUNIX -DW */
    x = ipcCreate(IPC_TCP_SOCKET,
#else
    x = ipcCreate(IPC_FIFO,
#endif
	Config.Program.unlinkd,
	args,
	"unlinkd",
	&unlinkd_rfd,
	&unlinkd_wfd);
    if (x < 0)
	fatal("Failed to create unlinkd subprocess");
    slp.tv_sec = 0;
    slp.tv_usec = 250000;
    select(0, NULL, NULL, NULL, &slp);
    fd_note(unlinkd_wfd, "squid -> unlinkd");
    fd_note(unlinkd_rfd, "unlinkd -> squid");
    commSetTimeout(unlinkd_rfd, -1, NULL, NULL);
    commSetTimeout(unlinkd_wfd, -1, NULL, NULL);
    /*
     * We leave unlinkd_wfd blocking, because we never want to lose an
     * unlink request, and we don't have code to retry if we get
     * EWOULDBLOCK.
     */
    commSetNonBlocking(unlinkd_rfd);
    debug(12, 1) ("Unlinkd pipe opened on FD %d\n", unlinkd_wfd);
#else
    debug(12, 1) ("Unlinkd is disabled\n");
#endif
}

#endif /* ndef UNLINK_DAEMON */
