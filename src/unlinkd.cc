/*
 * $Id: unlinkd.cc,v 1.2 1997/04/28 04:23:32 wessels Exp $
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

static char hello_string[] = "hi there\n";

#ifdef UNLINK_DAEMON

/* This is the external unlinkd process */

#include "config.h"
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
    write(1, hello_string, sizeof(hello_string));
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
int unlinkd_count;

static int unlinkdCreate _PARAMS((void));

#define HELLO_BUFSIZ 128
static int
unlinkdCreate(void)
{
    pid_t pid;
    int rfd1, rfd2, wfd1, wfd2;
    int squid_to_unlinkd[2] =
    {-1, -1};
    int unlinkd_to_squid[2] =
    {-1, -1};
    int n;
    char buf[HELLO_BUFSIZ];
    struct timeval slp;
    if (pipe(squid_to_unlinkd) < 0) {
	debug(50, 0, "unlinkdCreate: pipe: %s\n", xstrerror());
	return -1;
    }
    if (pipe(unlinkd_to_squid) < 0) {
	debug(50, 0, "unlinkdCreate: pipe: %s\n", xstrerror());
	return -1;
    }
    rfd1 = squid_to_unlinkd[0];
    wfd1 = squid_to_unlinkd[1];
    rfd2 = unlinkd_to_squid[0];
    wfd2 = unlinkd_to_squid[1];
    if ((pid = fork()) < 0) {
	debug(50, 0, "unlinkdCreate: fork: %s\n", xstrerror());
	close(rfd1);
	close(wfd1);
	close(rfd2);
	close(wfd2);
	return -1;
    }
    if (pid > 0) {		/* parent process */
	close(rfd1);
	close(wfd2);
	memset(buf, '\0', HELLO_BUFSIZ);
	n = read(rfd2, buf, HELLO_BUFSIZ - 1);
	close(rfd2);
	if (n <= 0) {
	    debug(50, 0, "unlinkdCreate: handshake failed\n");
	    close(wfd1);
	    return -1;
	} else if (strcmp(buf, hello_string)) {
	    debug(50, 0, "unlinkdCreate: handshake failed\n");
	    debug(50, 0, "--> got '%s'\n", rfc1738_escape(buf));
	    close(wfd1);
	    return -1;
	}
	comm_set_fd_lifetime(wfd1, -1);
	slp.tv_sec = 0;
	slp.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &slp);
	file_open_fd(wfd1, "unlinkd socket", FD_PIPE);
	commSetNonBlocking(wfd1);
	return wfd1;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    close(wfd1);
    close(rfd2);
    dup2(rfd1, 0);
    dup2(wfd2, 1);
    close(rfd1);		/* close FD since we dup'd it */
    close(wfd2);		/* close parent's FD */
    commSetCloseOnExec(fileno(debug_log));
    execlp(Config.Program.unlinkd, "(unlinkd)", NULL);
    debug(50, 0, "unlinkdCreate: %s: %s\n",
	Config.Program.unlinkd, xstrerror());
    _exit(1);
    return 0;
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
	buf,
	l,
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    unlinkd_count++;
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
    unlinkd_count = 0;
    unlinkd_fd = unlinkdCreate();
    if (unlinkd_fd < 0)
	fatal("unlinkdInit: failed to start unlinkd\n");
    fd_note(unlinkd_fd, Config.Program.unlinkd);
    debug(43, 0, "Unlinkd pipe opened on FD %d\n", unlinkd_fd);
}

#endif /* ndef UNLINK_DAEMON */
