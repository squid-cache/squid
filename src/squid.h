
/*
 * $Id: squid.h,v 1.122 1997/06/18 00:20:03 wessels Exp $
 *
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

#ifndef SQUID_H
#define SQUID_H

#include "config.h"

/*
 * On some systems, FD_SETSIZE is set to something lower than the
 * actual number of files which can be opened.  IRIX is one case,
 * NetBSD is another.  So here we increase FD_SETSIZE to our
 * configure-discovered maximum *before* any system includes.
 */
#define CHANGE_FD_SETSIZE 1

/* Cannot increase FD_SETSIZE on Linux */
#if defined(_SQUID_LINUX_)
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif

/* Cannot increase FD_SETSIZE on FreeBSD before 2.2.0, causes select(2)
 * to return EINVAL. */
/* Marian Durkovic <marian@svf.stuba.sk> */
/* Peter Wemm <peter@spinner.DIALix.COM> */
#if defined(_SQUID_FREEBSD_)
#include <osreldate.h>
#if __FreeBSD_version < 220000
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif
#endif

/* Increase FD_SETSIZE if SQUID_MAXFD is bigger */
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
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
#ifdef _SQUID_NEXT_
#include <netinet/in_systm.h>
#endif
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
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_POLL_H
#include <poll.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#else
#define assert(X) ((void)0)
#endif

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

/* Make sure syslog goes after stdarg/varargs */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#if HAVE_MATH_H
#include <math.h>
#endif

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif

#define SQUID_MAXPATHLEN 256
#ifndef MAXPATHLEN
#define MAXPATHLEN SQUID_MAXPATHLEN
#endif

#if !defined(HAVE_GETRUSAGE) && defined(_SQUID_HPUX_)
#define HAVE_GETRUSAGE 1
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
typedef struct _peer peer;
typedef struct icp_common_s icp_common_t;
typedef struct _cacheinfo cacheinfo;
typedef struct _aclCheck_t aclCheck_t;
typedef struct _request request_t;
typedef struct _MemObject MemObject;
typedef struct _cachemgr_passwd cachemgr_passwd;
typedef struct _fileMap fileMap;
typedef struct _cwstate CommWriteStateData;
typedef struct _ipcache_addrs ipcache_addrs;

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

#include "ansiproto.h"

#ifdef USE_GNUREGEX
#include "GNUregex.h"
#elif HAVE_REGEX_H
#include <regex.h>
#endif

typedef void SIH _PARAMS((void *, int));	/* swap in */
typedef int QS _PARAMS((const void *, const void *));	/* qsort */
typedef void STCB _PARAMS((void *, char *, size_t));	/* store callback */

#include "cache_cf.h"
#include "fd.h"
#include "comm.h"
#include "disk.h"
#include "debug.h"
#include "fdstat.h"
#include "hash.h"
#include "proto.h"		/* must go before neighbors.h */
#include "peer_select.h"	/* must go before neighbors.h */
#include "neighbors.h"		/* must go before url.h */
#include "url.h"
#include "icp.h"
#include "errorpage.h"		/* must go after icp.h */
#include "dns.h"
#include "event.h"
#include "ipcache.h"
#include "fqdncache.h"
#include "mime.h"
#include "stack.h"
#include "stat.h"
#include "stmem.h"
#include "store.h"
#include "store_dir.h"
#include "tools.h"
#include "http.h"
#include "ftp.h"
#include "gopher.h"
#include "util.h"
#include "acl.h"
#include "async_io.h"
#include "redirect.h"
#include "client_side.h"
#include "useragent.h"
#include "icmp.h"
#include "net_db.h"
#include "client_db.h"
#include "objcache.h"
#include "refresh.h"
#include "unlinkd.h"
#include "multicast.h"
#include "cbdata.h"

#if !HAVE_TEMPNAM
#include "tempnam.h"
#endif

extern void serverConnectionsClose _PARAMS((void));
extern void shut_down _PARAMS((int));


extern time_t squid_starttime;	/* main.c */
extern int do_reuse;		/* main.c */
extern int HttpSockets[];	/* main.c */
extern int NHttpSockets;	/* main.c */
extern int theInIcpConnection;	/* main.c */
extern int theOutIcpConnection;	/* main.c */
extern int vizSock;
extern volatile int shutdown_pending;	/* main.c */
extern volatile int reconfigure_pending;	/* main.c */
extern int opt_reload_hit_only;	/* main.c */
extern int opt_dns_tests;	/* main.c */
extern int opt_foreground_rebuild;	/* main.c */
extern int opt_zap_disk_store;	/* main.c */
extern int opt_syslog_enable;	/* main.c */
extern int opt_catch_signals;	/* main.c */
extern int opt_no_ipcache;	/* main.c */
extern int vhost_mode;		/* main.c */
extern int Squid_MaxFD;		/* main.c */
extern int Biggest_FD;		/* main.c */
extern int select_loops;	/* main.c */
extern const char *const version_string;	/* main.c */
extern const char *const appname;	/* main.c */
extern struct in_addr local_addr;	/* main.c */
extern struct in_addr theOutICPAddr;	/* main.c */
extern const char *const localhost;
extern struct in_addr no_addr;	/* comm.c */
extern int opt_udp_hit_obj;	/* main.c */
extern int opt_mem_pools;	/* main.c */
extern int opt_forwarded_for;	/* main.c */
extern int opt_accel_uses_host;	/* main.c */
extern int configured_once;	/* main.c */
extern char ThisCache[];	/* main.c */

/* Prototypes and definitions which don't really deserve a separate
 * include file */

#define  CONNECT_PORT        443

extern void start_announce _PARAMS((void *unused));
extern void sslStart _PARAMS((int fd, const char *, request_t *, int *sz));
extern void waisStart _PARAMS((request_t *, StoreEntry *));
extern void storeDirClean _PARAMS((void *unused));
extern void passStart _PARAMS((int, const char *, request_t *, int *));
extern void identStart _PARAMS((int, ConnStateData *, IDCB * callback));
extern int httpAnonAllowed _PARAMS((const char *line));
extern int httpAnonDenied _PARAMS((const char *line));

extern const char *const dash_str;
extern const char *const null_string;
extern const char *const w_space;

#define OR(A,B) (A ? A : B)

#endif /* SQUID_H */
