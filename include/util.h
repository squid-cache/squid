/*
 * $Id: util.h,v 1.6 1996/04/14 03:34:28 wessels Exp $
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
void xxfree _PARAMS((void *));			/* Wrapper for free(3) */
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
extern time_t parse_rfc850 _PARAMS((char *str));
extern void init_log3 _PARAMS((char *pn, FILE *a, FILE *b));
extern void debug_init();
extern void log_errno2 _PARAMS((char *, int, char *));

#if defined(__STRICT_ANSI__)
extern void Log _PARAMS((char *, ...));
extern void errorlog  _PARAMS((char *, ...));
#else
extern void Log ();
extern void errorlog ();
#endif /* __STRICT_ANSI__ */


#endif /* ndef _UTIL_H_ */
