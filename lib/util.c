/* $Id: util.c,v 1.3 1996/03/26 05:13:15 wessels Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>

void (*failure_notify) () = NULL;
static char msg[128];

extern int sys_nerr;
#if !defined(__FreeBSD__) && !defined(__NetBSD__)
extern char *sys_errlist[];
#endif

#include "autoconf.h"

/*
 *  xmalloc() - same as malloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *xmalloc(sz)
     size_t sz;
{
    static void *p;

    if (sz < 1)
	sz = 1;
    if ((p = malloc(sz)) == NULL) {
	if (failure_notify) {
	    sprintf(msg, "xmalloc: Unable to allocate %d bytes!\n",
		(int) sz);
	    (*failure_notify) (msg);
	} else {
	    perror("malloc");
	}
	exit(1);
    }
    return (p);
}

/*
 *  xfree() - same as free(3).  Will not call free(3) if s == NULL.
 */
void xfree(s)
     void *s;
{
    if (s != NULL) {
	free(s);
    }
}

/*
 *  xrealloc() - same as realloc(3). Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *xrealloc(s, sz)
     void *s;
     size_t sz;
{
    static void *p;

    if (sz < 1)
	sz = 1;
    if ((p = realloc(s, sz)) == NULL) {
	if (failure_notify) {
	    sprintf(msg, "xrealloc: Unable to reallocate %d bytes!\n",
		(int) sz);
	    (*failure_notify) (msg);
	} else {
	    perror("realloc");
	}
	exit(1);
    }
    return (p);
}

/*
 *  xcalloc() - same as calloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *xcalloc(n, sz)
     int n;
     size_t sz;
{
    static void *p;

    if (n < 1)
	n = 1;
    if (sz < 1)
	sz = 1;
    if ((p = calloc(n, sz)) == NULL) {
	if (failure_notify) {
	    sprintf(msg, "xcalloc: Unable to allocate %d blocks of %d bytes!\n",
		(int) n, (int) sz);
	    (*failure_notify) (msg);
	} else {
	    perror("xcalloc");
	}
	exit(1);
    }
    return (p);
}

/*
 *  xstrdup() - same as strdup(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
char *xstrdup(s)
     char *s;
{
    static char *p = NULL;
    int sz;

    if (s == NULL) {
	if (failure_notify) {
	    (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
	} else {
	    fprintf(stderr, "xstrdup: tried to dup a NULL pointer!\n");
	}
	exit(1);
    }
    sz = strlen(s);
    p = (char *) xmalloc((size_t) sz + 1);
    memcpy(p, s, sz);		/* copy string */
    p[sz] = '\0';		/* terminate string */
    return (p);
}

#ifndef HAVE_STRDUP
/* define for systems that don't have strdup */
char *strdup(s)
     char *s;
{
    return (xstrdup(s));
}
#endif

/*
 * xstrerror() - return sys_errlist[errno];
 */
char *xstrerror()
{
    static char xstrerror_buf[BUFSIZ];

    if (errno < 0 || errno >= sys_nerr)
	return ("Unknown");
    sprintf(xstrerror_buf, "(%d) %s", errno, sys_errlist[errno]);
    return xstrerror_buf;
    /* return (sys_errlist[errno]); */
}

#ifndef HAVE_STRERROR
char *strerror(n)
     int n;
{
    return (xstrerror(n));
}
#endif
