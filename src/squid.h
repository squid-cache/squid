
/*
 * $Id: squid.h,v 1.51 1996/09/17 16:39:05 wessels Exp $
 *
 * AUTHOR: Duane Wessels
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

#include "config.h"

#if SQUID_FD_SETSIZE > 256
#define FD_SETSIZE SQUID_FD_SETSIZE
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
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>	/* needs sys/time.h above it */
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
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_LIBC_H
#include <libc.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if USE_ASYNC_IO && HAVE_AIO_H
#include <aio.h>
#endif

#if defined(__STRICT_ANSI__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

/* Make sure syslog goes after stdarg/varargs */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

/* Only enable shadow password suite if both header and library exist */
#if HAVE_SHADOW_H && HAVE_LIBSHADOW
#include <shadow.h>
#endif

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

#if !defined(HAVE_RUSAGE) && defined(_SQUID_HPUX_)
#define HAVE_RUSAGE
#define getrusage(a, b)  syscall(SYS_GETRUSAGE, a, b)
#endif

#if !defined(HAVE_GETPAGESIZE) && defined(_SQUID_HPUX_)
#define HAVE_GETPAGESIZE
#define getpagesize( )   sysconf(_SC_PAGE_SIZE)
#endif

#ifndef BUFSIZ
#define BUFSIZ  4096		/* make reasonable guess */
#endif

#ifndef SA_RESTART
#define SA_RESTART 0
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND 0
#endif
#if SA_RESETHAND == 0 && defined(SA_ONESHOT)
#undef SA_RESETHAND
#define SA_RESETHAND SA_ONESHOT
#endif

typedef struct sentry StoreEntry;
typedef struct mem_hdr *mem_ptr;
typedef struct _edge edge;
typedef struct icp_common_s icp_common_t;
typedef struct _cacheinfo cacheinfo;
typedef struct _aclCheck_t aclCheck_t;
typedef struct _request request_t;

/* 32 bit integer compatability hack */
#if SIZEOF_INT == 4
typedef int num32;
typedef unsigned int u_num32;
#elif SIZEOF_LONG == 4
typedef long num32;
typedef unsigned long u_num32;
#else
typedef long num32;		/* assume that long's are 32bit */
typedef unsigned long u_num32;
#endif
#define NUM32LEN sizeof(num32)	/* this should always be 4 */

#if PURIFY
#define LOCAL_ARRAY(type,name,size) \
        static type *local_##name=NULL; \
        type *name = local_##name ? local_##name : \
                ( local_##name = (type *)xcalloc(size, sizeof(type)) )
#else
#define LOCAL_ARRAY(type,name,size) static type name[size]
#endif

#include "GNUregex.h"
#include "ansiproto.h"

typedef void (*SIH) (int, void *);	/* swap in */
typedef int (*QS) (const void *, const void *);

#include "cache_cf.h"
#include "comm.h"
#include "debug.h"
#include "disk.h"
#include "fdstat.h"
#include "filemap.h"
#include "hash.h"
#include "proto.h"		/* must go before neighbors.h */
#include "neighbors.h"		/* must go before url.h */
#include "url.h"
#include "icp.h"
#include "errorpage.h"		/* must go after icp.h */
#include "dns.h"
#include "ipcache.h"
#include "fqdncache.h"
#include "mime.h"
#include "stack.h"
#include "stat.h"
#include "stmem.h"
#include "store.h"
#include "tools.h"
#include "http.h"
#include "ftp.h"
#include "gopher.h"
#include "util.h"
#include "background.h"
#include "acl.h"
#include "async_io.h"
#include "redirect.h"
#include "client_side.h"
#include "icmp.h"

#if !HAVE_TEMPNAM
#include "tempnam.h"
#endif

extern void serverConnectionsClose __P((void));
extern void shut_down __P((int));


extern time_t squid_starttime;	/* main.c */
extern int do_reuse;		/* main.c */
extern int theHttpConnection;	/* main.c */
extern int theInIcpConnection;	/* main.c */
extern int theOutIcpConnection;	/* main.c */
extern volatile int shutdown_pending;   /* main.c */
extern volatile int reread_pending;     /* main.c */
extern int opt_unlink_on_reload;	/* main.c */
extern int opt_reload_hit_only;	/* main.c */
extern int opt_dns_tests;	/* main.c */
extern int opt_foreground_rebuild;	/* main.c */
extern int opt_zap_disk_store;	/* main.c */
extern int opt_syslog_enable;	/* main.c */
extern int opt_catch_signals;	/* main.c */
extern int opt_no_ipcache;	/* main.c */
extern int vhost_mode;		/* main.c */
extern char version_string[];	/* main.c */
extern char appname[];		/* main.c */
extern struct in_addr local_addr;	/* main.c */
extern char localhost[];
extern struct in_addr any_addr;	/* comm.c */
extern struct in_addr no_addr;	/* comm.c */

/* Prototypes and definitions which don't really deserve a seaprate
 * include file */

#define  CONNECT_PORT        443

extern int objcacheStart __P((int, char *, StoreEntry *));
extern void send_announce __P((void));
extern int sslStart __P((int fd, char *, request_t *, char *, int *sz));
extern char *storeToString __P((StoreEntry *));
extern void ttlSet __P((StoreEntry *));
extern void ttlFreeList __P((void));
extern void ttlAddToList __P((char *, int, int, time_t, int, time_t));
extern void ttlAddToForceList __P((char *, time_t, time_t));
extern int waisStart __P((int, char *, method_t, char *, StoreEntry *));
extern void storeDirClean __P((void));
extern char *dash_str;
