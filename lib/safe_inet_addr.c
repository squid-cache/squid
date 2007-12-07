
/*
 * $Id: safe_inet_addr.c,v 1.15 2007/12/06 18:01:52 rousskov Exp $
 */

#include "config.h"
#include "util.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif


int
safe_inet_addr(const char *buf, struct IN_ADDR *addr)
{
    static char addrbuf[32];
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0;
    struct IN_ADDR A;
    char x;
#if defined(_SQUID_HPUX_)
    /*
     * MIYOSHI Tsutomu <mijosxi@ike.tottori-u.ac.jp> says scanning 'buf'
     * causes a bus error on hppa1.1-hp-hpux9.07, so we
     * have a broad hack for all HP systems.
     */
    static char buftmp[32];
    snprintf(buftmp, 32, "%s", buf);
    if (sscanf(buftmp, "%d.%d.%d.%d%c", &a1, &a2, &a3, &a4, &x) != 4)
#else
    if (sscanf(buf, "%d.%d.%d.%d%c", &a1, &a2, &a3, &a4, &x) != 4)
#endif
	return 0;
    if (a1 < 0 || a1 > 255)
	return 0;
    if (a2 < 0 || a2 > 255)
	return 0;
    if (a3 < 0 || a3 > 255)
	return 0;
    if (a4 < 0 || a4 > 255)
	return 0;
    snprintf(addrbuf, 32, "%d.%d.%d.%d", a1, a2, a3, a4);
    A.s_addr = inet_addr(addrbuf);
    if (addr)
	addr->s_addr = A.s_addr;
    return 1;
}
