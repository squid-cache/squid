/*
 * $Id: unlinkd.cc,v 1.14 1998/02/02 07:20:58 wessels Exp $
 *
 * DEBUG: section 43    Unlink Daemon
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

#ifdef UNLINK_DAEMON

/* This is the external unlinkd process */

#include "config.h"

#if HAVE_LIBC_H
#include <libc.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#define UNLINK_BUF_LEN 1024

int
main(int argc, char *argv[])
{
    char buf[UNLINK_BUF_LEN];
    char *t;
    setbuf(stdin, NULL);
    while (fgets(buf, UNLINK_BUF_LEN, stdin)) {
	if ((t = strchr(buf, '\n')))
	    *t = '\0';
	unlink(buf);
    }
    exit(0);
}

#else /* UNLINK_DAEMON */

/* This code gets linked to Squid */

#include "squid.h"

static int unlinkd_fd = -1;

static int unlinkdCreate(void);

static int
unlinkdCreate(void)
{
	int x;
	int rfd;
	int wfd;
	char *args[2];
	struct timeval slp;
	args[0] = "(unlinkd)";
	args[1] = NULL;
	x = ipcCreate(IPC_FIFO,
		Config.Program.unlinkd,
		args,
		"unlinkd",
		&rfd,
		&wfd);
	if (x < 0)
		return -1;
	slp.tv_sec = 0;
	slp.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &slp);
	fd_note(wfd, "squid -> unlinkd");
	fd_note(rfd, "unlinkd -> squid");
	commSetTimeout(rfd, -1, NULL, NULL);
	commSetTimeout(wfd, -1, NULL, NULL);
	commSetNonBlocking(wfd);
	return wfd;
}

void
unlinkdUnlink(const char *path)
{
    char *buf;
    int l;
    if (unlinkd_fd < 0) {
	debug_trap("unlinkdUnlink: unlinkd_fd < 0");
	safeunlink(path, 0);
	return;
    }
    l = strlen(path) + 1;
    buf = xcalloc(1, l + 1);
    strcpy(buf, path);
    strcat(buf, "\n");
    file_write(unlinkd_fd,
	-1,
	buf,
	l,
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    Counter.unlink.requests++;
}

void
unlinkdClose(void)
{
    if (unlinkd_fd < 0) {
	debug_trap("unlinkdClose: unlinkd_fd < 0");
	return;
    }
    file_close(unlinkd_fd);
    unlinkd_fd = -1;
}

void
unlinkdInit(void)
{
    unlinkd_fd = unlinkdCreate();
    if (unlinkd_fd < 0)
	fatal("unlinkdInit: failed to start unlinkd\n");
    debug(43, 0) ("Unlinkd pipe opened on FD %d\n", unlinkd_fd);
}

#endif /* ndef UNLINK_DAEMON */
