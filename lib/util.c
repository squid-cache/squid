/*
 * $Id: util.c,v 1.14 1996/09/15 07:04:02 wessels Exp $
 *
 * DEBUG: 
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

#include "util.h"

void (*failure_notify) __P((char *)) = NULL;
static char msg[128];

extern int sys_nerr;
#if NEED_SYS_ERRLIST && !defined(_SQUID_NETBSD_)
extern char *sys_errlist[];
#endif

#if XMALLOC_STATISTICS
#define DBG_MAXSIZE   (1024*1024)
#define DBG_GRAIN     (16)
#define DBG_MAXINDEX  (DBG_MAXSIZE/DBG_GRAIN)
#define DBG_INDEX(sz) (sz<DBG_MAXSIZE?(sz+DBG_GRAIN-1)/DBG_GRAIN:DBG_MAXINDEX)
static int malloc_sizes[DBG_MAXINDEX + 1];
static int dbg_stat_init = 0;

static void
stat_init()
{
    int i;
    for (i = 0; i <= DBG_MAXINDEX; i++)
	malloc_sizes[i] = 0;
    dbg_stat_init = 1;
}

static int
malloc_stat(int sz)
{
    if (!dbg_stat_init)
	stat_init();
    return malloc_sizes[DBG_INDEX(sz)] += 1;
}

void
malloc_statistics(void (*func) (int, int, void *), void *data)
{
    int i;
    for (i = 0; i <= DBG_MAXSIZE; i += DBG_GRAIN)
	func(i, malloc_sizes[DBG_INDEX(i)], data);
}
#endif /* XMALLOC_STATISTICS */



#if XMALLOC_DEBUG
#define DBG_ARRY_SZ (1<<10)
#define DBG_ARRY_BKTS (1<<8)
static void *malloc_ptrs[DBG_ARRY_BKTS][DBG_ARRY_SZ];
static int malloc_size[DBG_ARRY_BKTS][DBG_ARRY_SZ];
static int dbg_initd = 0;
static int B = 0;
static int I = 0;
static void *P;
static void *Q;

static void
check_init()
{
    for (B = 0; B < DBG_ARRY_BKTS; B++) {
	for (I = 0; I < DBG_ARRY_SZ; I++) {
	    malloc_ptrs[B][I] = NULL;
	    malloc_size[B][I] = 0;
	}
    }
    dbg_initd = 1;
}

static void
check_free(void *s)
{
    B = (((int) s) >> 4) & 0xFF;
    for (I = 0; I < DBG_ARRY_SZ; I++) {
	if (malloc_ptrs[B][I] != s)
	    continue;
	malloc_ptrs[B][I] = NULL;
	malloc_size[B][I] = 0;
	break;
    }
    if (I == DBG_ARRY_SZ) {
	sprintf(msg, "xfree: ERROR: s=%p not found!", s);
	(*failure_notify) (msg);
    }
}

static void
check_malloc(void *p, size_t sz)
{
    if (!dbg_initd)
	check_init();
    B = (((int) p) >> 4) & 0xFF;
    for (I = 0; I < DBG_ARRY_SZ; I++) {
	if ((P = malloc_ptrs[B][I]) == NULL)
	    continue;
	Q = P + malloc_size[B][I];
	if (P <= p && p < Q) {
	    sprintf(msg, "xmalloc: ERROR: p=%p falls in P=%p+%d",
		p, P, malloc_size[B][I]);
	    (*failure_notify) (msg);
	}
    }
    for (I = 0; I < DBG_ARRY_SZ; I++) {
	if ((P = malloc_ptrs[B][I]))
	    continue;
	malloc_ptrs[B][I] = p;
	malloc_size[B][I] = (int) sz;
	break;
    }
    if (I == DBG_ARRY_SZ)
	(*failure_notify) ("xmalloc: debug out of array space!");
}
#endif

#if XMALLOC_COUNT && !HAVE_MALLOCBLKSIZE
int
mallocblksize(void *p)
{
    B = (((int) p) >> 4) & 0xFF;
    for (I = 0; I < DBG_ARRY_SZ; I++) {
	if (malloc_ptrs[B][I] == p)
	    return malloc_size[B][I];
    }
    return 0;
}
#endif

#ifdef XMALLOC_COUNT
static void
xmalloc_count(void *p, int sign)
{
    size_t sz;
    static size_t total = 0;
    int memoryAccounted();
    int mallinfoTotal();
    sz = mallocblksize(p) * sign;
    total += sz;
    fprintf(stderr, "xmalloc_count=%9d  accounted=%9d  mallinfo=%9d\n",
	(int) total,
	memoryAccounted(),
	mallinfoTotal());
}

#endif /* XMALLOC_COUNT */

/*
 *  xmalloc() - same as malloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xmalloc(size_t sz)
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
#if XMALLOC_DEBUG
    check_malloc(p, sz);
#endif
#if XMALLOC_STATISTICS
    malloc_stat(sz);
#endif
#if XMALLOC_COUNT
    xmalloc_count(p, 1);
#endif
    return (p);
}

/*
 *  xfree() - same as free(3).  Will not call free(3) if s == NULL.
 */
void
xfree(void *s)
{
#if XMALLOC_COUNT
    xmalloc_count(s, -1);
#endif
#if XMALLOC_DEBUG
    check_free(s);
#endif
    if (s != NULL)
	free(s);
}

/* xxfree() - like xfree(), but we already know s != NULL */
void
xxfree(void *s)
{
#if XMALLOC_COUNT
    xmalloc_count(s, -1);
#endif
#if XMALLOC_DEBUG
    check_free(s);
#endif
    free(s);
}

/*
 *  xrealloc() - same as realloc(3). Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xrealloc(void *s, size_t sz)
{
    static void *p;

#if XMALLOC_COUNT
    xmalloc_count(s, -1);
#endif

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
#if XMALLOC_DEBUG
    check_malloc(p, sz);
#endif
#if XMALLOC_STATISTICS
    malloc_stat(sz);
#endif
#if XMALLOC_COUNT
    xmalloc_count(p, 1);
#endif
    return (p);
}

/*
 *  xcalloc() - same as calloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xcalloc(int n, size_t sz)
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
#if XMALLOC_DEBUG
    check_malloc(p, sz * n);
#endif
#if XMALLOC_STATISTICS
    malloc_stat(sz);
#endif
#if XMALLOC_COUNT
    xmalloc_count(p, 1);
#endif
    return (p);
}

/*
 *  xstrdup() - same as strdup(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
char *
xstrdup(char *s)
{
    static char *p = NULL;
    size_t sz;

    if (s == NULL) {
	if (failure_notify) {
	    (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
	} else {
	    fprintf(stderr, "xstrdup: tried to dup a NULL pointer!\n");
	}
	exit(1);
    }
    sz = strlen(s);
    p = xmalloc((size_t) sz + 1);
    memcpy(p, s, sz);		/* copy string */
    p[sz] = '\0';		/* terminate string */
    return (p);
}

/*
 * xstrerror() - return sys_errlist[errno];
 */
char *
xstrerror()
{
    static char xstrerror_buf[BUFSIZ];

    if (errno < 0 || errno >= sys_nerr)
	return ("Unknown");
    sprintf(xstrerror_buf, "(%d) %s", errno, sys_errlist[errno]);
    return xstrerror_buf;
    /* return (sys_errlist[errno]); */
}

#if !HAVE_STRDUP
/* define for systems that don't have strdup */
char *
strdup(char *s)
{
    return (xstrdup(s));
}
#endif

void
xmemcpy(void *from, void *to, int len)
{
#if HAVE_MEMMOVE
    (void) memmove(from, to, len);
#elif HAVE_BCOPY
    bcopy(to, from, len);
#else
    (void) memcpy(from, to, len);
#endif
}

void
Tolower(char *q)
{
    char *s = q;
    while (*s) {
	*s = tolower((unsigned char) *s);
	s++;
    }
}
