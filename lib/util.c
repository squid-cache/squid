static char rcsid[] = "$Id: util.c,v 1.1 1996/02/22 06:23:58 wessels Exp $";
/*
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>

void (*failure_notify) () = NULL;
static char msg[128];

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
    extern int sys_nerr;
#if !defined(__FreeBSD__) && !defined(__NetBSD__)
    extern char *sys_errlist[];
#endif
    int n;

    n = errno;
    if (n < 0 || n >= sys_nerr)
	return ("Unknown");
    return (sys_errlist[n]);
}

#ifndef HAVE_STRERROR
char *strerror(n)
     int n;
{
    return (xstrerror(n));
}
#endif
