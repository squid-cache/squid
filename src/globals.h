
/*
 * $Id: globals.h,v 1.18 1997/11/15 00:14:48 wessels Exp $
 */

extern FILE *debug_log;		/* NULL */
extern FILE *cache_useragent_log;	/* NULL */
extern Meta_data meta_data;
extern SquidConfig Config;
extern SquidConfig2 Config2;
extern cacheinfo *HTTPCacheInfo;
extern cacheinfo *ICPCacheInfo;
extern char *ConfigFile;	/* NULL */
extern char *IcpOpcodeStr[];
extern char *dns_error_message;	/* NULL */
extern const char *log_tags[];
extern char tmp_error_buf[ERROR_BUF_SZ];
extern char *volatile debug_options;	/* NULL */
extern char ThisCache[SQUIDHOSTNAMELEN << 1];
extern char config_input_line[BUFSIZ];
extern const char *AclMatchedName;	/* NULL */
extern const char *DefaultConfigFile;	/* DEFAULT_CONFIG_FILE */
extern const char *RequestMethodStr[];
extern const char *ProtocolStr[];
extern const char *cfg_filename;	/* NULL */
extern const char *const appname;	/* "squid" */
extern const char *const close_bracket;		/* "}\n" */
extern const char *const dash_str;	/* "-" */
extern const char *const localhost;	/* "127.0.0.1" */
extern const char *const null_string;	/* "" */
extern const char *const open_bracket;	/* "{\n" */
extern const char *const version_string;	/* SQUID_VERSION */
extern const char *const w_space;	/* " \t\n\r" */
extern const char *fdstatTypeStr[];
extern const char *hier_strings[];
extern const char *memStatusStr[];
extern const char *pingStatusStr[];
extern const char *storeStatusStr[];
extern const char *swapStatusStr[];
extern dnsStatData DnsStats;
extern fde *fd_table;		/* NULL */
extern int Biggest_FD;		/* -1 */
extern int Number_FD;		/* 0 */
extern int HttpSockets[MAXHTTPPORTS];
extern int NDnsServersAlloc;	/* 0 */
extern int NHttpSockets;	/* 0 */
extern int RESERVED_FD;
extern int Squid_MaxFD;		/* SQUID_MAXFD */
extern int config_lineno;	/* 0 */
extern int configured_once;	/* 0 */
extern int debugLevels[MAX_DEBUG_SECTIONS];
extern int do_mallinfo;		/* 0 */
extern int do_reuse;		/* 1 */
extern int hash_links_allocated;
extern int icmp_sock;		/* -1 */
extern int neighbors_do_private_keys;	/* 1 */
extern int opt_accel_uses_host;	/* 0 */
extern int opt_catch_signals;	/* 1 */
extern int opt_debug_stderr;	/* 0 */
extern int opt_dns_tests;	/* 1 */
extern int opt_foreground_rebuild;	/* 0 */
extern int opt_forwarded_for;	/* 1 */
extern int opt_mem_pools;	/* 1 */
extern int opt_reload_hit_only;	/* 0 */
extern int opt_syslog_enable;	/* 0 */
extern int opt_udp_hit_obj;	/* 0 */
extern int opt_zap_disk_store;	/* 0 */
extern int syslog_enable;	/* 0 */
extern int theInIcpConnection;	/* -1 */
extern int theOutIcpConnection;	/* -1 */
extern int vhost_mode;		/* 0 */
extern int vizSock;		/* -1 */
extern iostats IOStats;
extern stmem_stats disk_stats;
extern stmem_stats mem_obj_pool;
extern stmem_stats request_pool;
extern stmem_stats sm_stats;
extern struct _acl_deny_info_list *DenyInfoList;	/* NULL */
extern struct in_addr any_addr;
extern struct in_addr local_addr;
extern struct in_addr no_addr;
extern struct in_addr theOutICPAddr;
extern struct timeval current_time;
extern struct timeval squid_start;
extern time_t squid_curtime;	/* 0 */
extern volatile int reconfigure_pending;	/* 0 */
extern volatile int shutdown_pending;	/* 0 */
extern int fileno_stack_count;	/* 0 */
extern int store_rebuilding;	/* 1 */
extern int store_swap_size;	/* 0 */
extern int client_info_sz;	/* 0 */
extern unsigned long store_mem_size;	/* 0 */
extern icpUdpData *UdpQueueHead;	/* NULL */
extern icpUdpData *UdpQueueTail;	/* NULL */
extern time_t hit_only_mode_until;	/* 0 */
extern StatCounters Counter;

#ifdef HAVE_SYSLOG
extern int _db_level;
#endif
