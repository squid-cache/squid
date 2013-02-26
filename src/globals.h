/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_GLOBALS_H
#define SQUID_GLOBALS_H

#include "acl/AclDenyInfoList.h"
#include "CacheDigest.h"
#include "defines.h"
#include "hash.h"
#include "IoStats.h"
#include "rfc2181.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif

extern char *ConfigFile;	/* NULL */
extern char *IcpOpcodeStr[];
extern char tmp_error_buf[ERROR_BUF_SZ];
extern char ThisCache[RFC2181_MAXHOSTNAMELEN << 1];
extern char ThisCache2[RFC2181_MAXHOSTNAMELEN << 1];
extern char config_input_line[BUFSIZ];
extern const char *DefaultConfigFile;	/* DEFAULT_CONFIG_FILE */
extern const char *cfg_filename;	/* NULL */
extern const char *dash_str;	/* "-" */
extern const char *null_string;	/* "" */
extern const char *version_string;	/* VERSION */
extern const char *appname_string;	/* PACKAGE */
extern char const *visible_appname_string; /* NULL */
extern const char *fdTypeStr[];
extern const char *hier_strings[];
extern const char *memStatusStr[];
extern const char *pingStatusStr[];
extern const char *storeStatusStr[];
extern const char *swapStatusStr[];
extern int Biggest_FD;		/* -1 */
extern int Number_FD;		/* 0 */
extern int Opening_FD;		/* 0 */
extern int NDnsServersAlloc;	/* 0 */
extern int RESERVED_FD;
extern int Squid_MaxFD;		/* SQUID_MAXFD */
extern int config_lineno;	/* 0 */
extern int do_mallinfo;		/* 0 */
extern int opt_reuseaddr;	/* 1 */
extern int neighbors_do_private_keys;	/* 1 */
extern int opt_catch_signals;	/* 1 */
extern int opt_foreground_rebuild;	/* 0 */
extern char *opt_forwarded_for;	/* NULL */
extern int opt_reload_hit_only;	/* 0 */

extern int opt_udp_hit_obj;	/* 0 */
extern int opt_create_swap_dirs;	/* 0 */
extern int opt_store_doublecheck;	/* 0 */
extern int syslog_enable;	/* 0 */
extern int DnsSocketA;		/* -1 */
extern int DnsSocketB;		/* -1 */
extern int n_disk_objects;	/* 0 */
extern IoStats IOStats;

extern AclDenyInfoList *DenyInfoList;	/* NULL */

extern struct timeval squid_start;
extern int starting_up;	/* 1 */
extern int shutting_down;	/* 0 */
extern int reconfiguring;	/* 0 */
extern time_t hit_only_mode_until;	/* 0 */
extern double request_failure_ratio;	/* 0.0 */
extern int store_hash_buckets;	/* 0 */
extern hash_table *store_table;	/* NULL */
extern int hot_obj_count;	/* 0 */
extern int CacheDigestHashFuncCount;	/* 4 */
extern CacheDigest *store_digest;	/* NULL */
extern const char *StoreDigestFileName;		/* "store_digest" */
extern const char *StoreDigestMimeStr;	/* "application/cache-digest" */

extern const char *MultipartMsgBoundaryStr;	/* "Unique-Squid-Separator" */
#if USE_HTTP_VIOLATIONS
extern int refresh_nocache_hack;	/* 0 */
#endif

extern int store_open_disk_fd;	/* 0 */
extern const char *SwapDirType[];
extern int store_swap_low;	/* 0 */
extern int store_swap_high;	/* 0 */
extern size_t store_pages_max;	/* 0 */
extern int64_t store_maxobjsize;	/* -1 */
extern hash_table *proxy_auth_username_cache;	/* NULL */
extern int incoming_sockets_accepted;
#if _SQUID_MSWIN_
extern unsigned int WIN32_Socks_initialized;	/* 0 */
#endif
#if _SQUID_WINDOWS_
extern unsigned int WIN32_OS_version;	/* 0 */
extern char *WIN32_OS_string;           /* NULL */
extern char *WIN32_Service_name;        /* NULL */
extern char *WIN32_Command_Line;        /* NULL */
extern char *WIN32_Service_Command_Line; /* NULL */
extern unsigned int WIN32_run_mode;     /* _WIN_SQUID_RUN_MODE_INTERACTIVE */
#endif
#if HAVE_SBRK
extern void *sbrk_start;	/* 0 */
#endif

extern int ssl_ex_index_server;	/* -1 */
extern int ssl_ctx_ex_index_dont_verify_domain; /* -1 */
extern int ssl_ex_index_cert_error_check;	/* -1 */
extern int ssl_ex_index_ssl_error_detail;      /* -1 */
extern int ssl_ex_index_ssl_peeked_cert;      /* -1 */
extern int ssl_ex_index_ssl_errors;   /* -1 */

extern const char *external_acl_message;      /* NULL */
extern int opt_send_signal;	/* -1 */
extern int opt_no_daemon; /* 0 */
extern int opt_parse_cfg_only; /* 0 */

/// current Squid process number (e.g., 4).
/// Zero for SMP-unaware code and in no-SMP mode.
extern int KidIdentifier; /* 0 */

#endif /* SQUID_GLOBALS_H */
