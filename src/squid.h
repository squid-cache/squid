
/* $Id: squid.h,v 1.17 1996/04/15 22:56:06 wessels Exp $ */

#include "config.h"
#include "autoconf.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <malloc.h>
#include <memory.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>	/* needs sys/time.h above it */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>

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

#if defined(__STRICT_ANSI__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

/* Make sure syslog goes after stdarg/varargs */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif

typedef struct sentry StoreEntry;
typedef struct mem_hdr *mem_ptr;
typedef struct _edge edge;
typedef struct icp_common_s icp_common_t;
typedef struct _cacheinfo cacheinfo;

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

#include "GNUregex.h"
#include "ansihelp.h"
#include "cache_cf.h"
#include "comm.h"
#include "debug.h"
#include "disk.h"
#include "dynamic_array.h"
#include "fdstat.h"
#include "filemap.h"
#include "hash.h"
#include "url.h"
#include "proto.h"
#include "icp.h"
#include "cached_error.h"	/* must go after icp.h */
#include "ipcache.h"
#include "mime.h"
#include "neighbors.h"
#include "stack.h"
#include "stat.h"
#include "stmem.h"
#include "store.h"
#include "tools.h"
#include "ttl.h"
#include "storetoString.h"
#include "http.h"
#include "ftp.h"
#include "gopher.h"
#include "wais.h"
#include "connect.h"
#include "objcache.h"
#include "send-announce.h"
#include "acl.h"
#include "util.h"
#include "background.h"

extern time_t cached_starttime;	/* main.c */
extern time_t next_cleaning;	/* main.c */
extern int catch_signals;	/* main.c */
extern int do_reuse;		/* main.c */
extern int theAsciiConnection;	/* main.c */
extern int theUdpConnection;	/* main.c */
extern int shutdown_pending;	/* main.c */
extern int reread_pending;	/* main.c */
extern int opt_unlink_on_reload;	/* main.c */
extern int vhost_mode;		/* main.c */
extern char *version_string;	/* main.c */
