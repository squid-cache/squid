
/*
 * $Id: globals.h,v 1.85 1999/07/13 14:51:13 wessels Exp $
 *
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

extern FILE *debug_log;		/* NULL */
extern FILE *cache_useragent_log;	/* NULL */
extern SquidConfig Config;
extern SquidConfig2 Config2;
extern char *ConfigFile;	/* NULL */
extern char *IcpOpcodeStr[];
extern char *dns_error_message;	/* NULL */
extern const char *log_tags[];
extern char tmp_error_buf[ERROR_BUF_SZ];
extern char *volatile debug_options;	/* NULL */
extern char ThisCache[SQUIDHOSTNAMELEN << 1];
extern char ThisCache2[SQUIDHOSTNAMELEN << 1];
extern char config_input_line[BUFSIZ];
extern const char *AclMatchedName;	/* NULL */
extern const char *DefaultConfigFile;	/* DEFAULT_CONFIG_FILE */
extern const char *RequestMethodStr[];
extern const char *ProtocolStr[];
extern const char *cfg_filename;	/* NULL */
extern const char *const appname;	/* "squid" */
extern const char *const dash_str;	/* "-" */
extern const char *const localhost;	/* "127.0.0.1" */
extern const char *const null_string;	/* "" */
extern const char *const version_string;	/* SQUID_VERSION */
extern const char *const full_appname_string;	/* "Squid/" SQUID_VERSION */
extern const char *const w_space;	/* " \t\n\r" */
extern const char *fdTypeStr[];
extern const char *hier_strings[];
extern const char *memStatusStr[];
extern const char *pingStatusStr[];
extern const char *storeStatusStr[];
extern const char *swapStatusStr[];
extern dnsStatData DnsStats;
extern fde *fd_table;		/* NULL */
extern int Biggest_FD;		/* -1 */
extern int Number_FD;		/* 0 */
extern int Opening_FD;		/* 0 */
extern int HttpSockets[MAXHTTPPORTS];
extern int NDnsServersAlloc;	/* 0 */
extern int NHttpSockets;	/* 0 */
extern int RESERVED_FD;
extern int Squid_MaxFD;		/* SQUID_MAXFD */
extern int config_lineno;	/* 0 */
extern int debugLevels[MAX_DEBUG_SECTIONS];
extern int do_mallinfo;		/* 0 */
extern int opt_reuseaddr;	/* 1 */
extern int icmp_sock;		/* -1 */
extern int neighbors_do_private_keys;	/* 1 */
extern int opt_accel_uses_host;	/* 0 */
extern int opt_catch_signals;	/* 1 */
extern int opt_debug_stderr;	/* -1 */
extern int opt_dns_tests;	/* 1 */
extern int opt_foreground_rebuild;	/* 0 */
extern int opt_forwarded_for;	/* 1 */
extern int opt_reload_hit_only;	/* 0 */
extern int opt_syslog_enable;	/* 0 */
extern int opt_udp_hit_obj;	/* 0 */
extern int opt_create_swap_dirs;	/* 0 */
extern int opt_store_doublecheck;	/* 0 */
extern int syslog_enable;	/* 0 */
extern int theInIcpConnection;	/* -1 */
extern int theOutIcpConnection;	/* -1 */
extern int DnsSocket;		/* -1 */
#ifdef SQUID_SNMP
extern int theInSnmpConnection;	/* -1 */
extern int theOutSnmpConnection;	/* -1 */
extern char *snmp_agentinfo;
#endif
extern int vhost_mode;		/* 0 */
extern int n_disk_objects;	/* 0 */
extern iostats IOStats;
extern struct _acl_deny_info_list *DenyInfoList;	/* NULL */
extern struct in_addr any_addr;
extern struct in_addr local_addr;
extern struct in_addr no_addr;
extern struct in_addr theOutICPAddr;
extern struct in_addr theOutSNMPAddr;
extern struct timeval current_time;
extern struct timeval squid_start;
extern time_t squid_curtime;	/* 0 */
extern int shutting_down;	/* 0 */
extern int reconfiguring;	/* 0 */
extern int store_dirs_rebuilding;	/* 0 */
extern int store_swap_size;	/* 0 */
extern unsigned long store_mem_size;	/* 0 */
extern time_t hit_only_mode_until;	/* 0 */
extern StatCounters Counter;
extern char *err_type_str[];
extern char *icp_opcode_str[];
extern char *swap_log_op_str[];
extern char *lookup_t_str[];
extern double request_failure_ratio;	/* 0.0 */
extern double current_dtime;
extern int store_hash_buckets;	/* 0 */
extern hash_table *store_table;	/* NULL */
#if HEAP_REPLACEMENT
extern heap *store_heap;
extern heap *inmem_heap;
#else
extern dlink_list store_list;
#endif
extern dlink_list ClientActiveRequests;
extern const String StringNull;	/* { 0, 0, NULL } */
extern const MemBuf MemBufNull;	/* MemBufNULL */
extern int hot_obj_count;	/* 0 */
extern int _db_level;
extern const int CacheDigestHashFuncCount;	/* 4 */
extern CacheDigest *store_digest;	/* NULL */
extern const char *StoreDigestFileName;		/* "store_digest" */
extern const char *StoreDigestMimeStr;	/* "application/cache-digest" */
#if USE_CACHE_DIGESTS
extern const Version CacheDigestVer;	/* { 5, 3 } */
#endif
extern const char *MultipartMsgBoundaryStr;	/* "Unique-Squid-Separator" */
extern icpUdpData *IcpQueueHead;	/* NULL */
#if HTTP_VIOLATIONS
extern int refresh_nocache_hack;	/* 0 */
#endif
extern request_flags null_request_flags;
extern int store_open_disk_fd;	/* 0 */
extern const char *SwapDirType[];
