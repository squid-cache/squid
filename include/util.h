/*
 *  Darren Hardy, hardy@cs.colorado.edu, April 1994
 *
 *  $Id: util.h,v 1.1 1996/02/22 06:23:56 wessels Exp $
 *
 *  ----------------------------------------------------------------------
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
 */
#ifndef _UTIL_H_
#define _UTIL_H_

#include "config.h"
#include <stdio.h>
#include <time.h>

#if !defined(SQUIDHOSTNAMELEN)
#include <sys/param.h>
#include <netdb.h>
#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif
#endif

#ifndef _PARAMS
#if defined(__STDC__) || defined(__cplusplus) || defined(__STRICT_ANSI__)
#define _PARAMS(ARGS) ARGS
#else /* Traditional C */     
#define _PARAMS(ARGS) ()      
#endif /* __STDC__ */              
#endif /* _PARAMS */   

#ifdef NO_STRDUP
char *strdup _PARAMS((char *));			/* Duplicate a string */
#endif
char *xstrdup _PARAMS((char *));		/* Duplicate a string */

/* from xmalloc.c */
void *xmalloc _PARAMS((size_t));		/* Wrapper for malloc(3) */
void *xrealloc _PARAMS((void *, size_t));	/* Wrapper for realloc(3) */
void *xcalloc _PARAMS((int, size_t));		/* Wrapper for calloc(3) */
void xfree _PARAMS((void *));			/* Wrapper for free(3) */
char *xstrdup _PARAMS ((char *));
char *xstrerror _PARAMS(());

char *getfullhostname _PARAMS(());

/* from debug.c */
#ifndef MAX_DEBUG_LEVELS
#define MAX_DEBUG_LEVELS 256
#endif /* MAX_DEBUG_LEVELS */

#ifndef MAIN
extern int Harvest_do_debug;
extern int Harvest_debug_levels[];
#endif	/* MAIN */

#undef debug_ok_fast
#if USE_NO_DEBUGGING
#define debug_ok_fast(S,L) 0
#else
#define debug_ok_fast(S,L) \
        ( \
        (Harvest_do_debug) && \
        ((Harvest_debug_levels[S] == -2) || \
         ((Harvest_debug_levels[S] != -1) && \
           ((L) <= Harvest_debug_levels[S]))) \
        )
#endif /* USE_NO_DEBUGGING */

#undef Debug
#if USE_NO_DEBUGGING
#define Debug(section, level, X) /* empty */;
#else
#define Debug(section, level, X) \
        {if (debug_ok_fast((section),(level))) {Log X;}}
#endif

void debug_reset _PARAMS((void));
void debug_enable _PARAMS((int, int));
void debug_disable _PARAMS((int));
void debug_flag _PARAMS((char *));
int  debug_ok _PARAMS((int, int));

#define HOST_CACHE_TTL 3600

typedef struct _host {
    char        key[SQUIDHOSTNAMELEN];    /* www.bar.com */
    char        fqdn[SQUIDHOSTNAMELEN];   /* real.bar.com */
    char        dotaddr[16];            /* 128.138.213.10 */
    char        ipaddr[4];
    time_t      last_t;                 /* last access of this info */
    int         n;                      /* # of requests for this host */
    int         addrlen;                /* length of 'ipaddr', always 4 */
    struct _host *next;
} Host;

extern Host   *thisHost;

void   host_cache_init _PARAMS((void));
Host  *get_host _PARAMS((char *hostname));
int   delete_host _PARAMS((Host *h));
int   expire_host_cache _PARAMS((time_t timeout));
void  dump_host_cache _PARAMS((int, int));



char *mkhttpdlogtime _PARAMS((time_t *));
extern char *mkrfc850 _PARAMS((time_t *));
extern void init_log3 _PARAMS((char *pn, FILE *a, FILE *b));
extern void debug_init();
extern void log_errno2 _PARAMS((char *, int, char *));

#endif /* ndef _UTIL_H_ */
