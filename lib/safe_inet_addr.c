#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

int
safe_inet_addr(const char *buf, struct in_addr *addr)
{
    static char addrbuf[32];
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0;
    struct in_addr A;
    if (sscanf(buf, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) != 4)
	return 0;
    if (a1 < 0 || a1 > 255)
	return 0;
    if (a2 < 0 || a2 > 255)
	return 0;
    if (a3 < 0 || a3 > 255)
	return 0;
    if (a4 < 0 || a4 > 255)
	return 0;
    sprintf(addrbuf, "%d.%d.%d.%d", a1, a2, a3, a4);
    A.s_addr = inet_addr(addrbuf);
    if (addr)
	addr->s_addr = A.s_addr;
    return 1;
}
