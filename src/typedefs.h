
/*
 * $Id: typedefs.h,v 1.93 1999/05/25 22:05:59 wessels Exp $
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

typedef unsigned int store_status_t;
typedef unsigned int mem_status_t;
typedef unsigned int ping_status_t;
typedef unsigned int swap_status_t;
typedef int sfileno;

typedef struct {
    size_t bytes;
    size_t kb;
} kb_t;

typedef struct {
    size_t count;
    size_t bytes;
    size_t gb;
} gb_t;

/*
 * grep '^struct' structs.h \
 * | perl -ne '($a,$b)=split;$c=$b;$c=~s/^_//; print "typedef struct $b $c;\n";'
 */

typedef struct _acl_ip_data acl_ip_data;
typedef struct _acl_time_data acl_time_data;
typedef struct _acl_name_list acl_name_list;
typedef struct _acl_deny_info_list acl_deny_info_list;
typedef struct _acl_proxy_auth acl_proxy_auth;
typedef struct _acl_proxy_auth_user acl_proxy_auth_user;
typedef struct _acl_arp_data acl_arp_data;
typedef struct _acl acl;
typedef struct _acl_snmp_comm acl_snmp_comm;
typedef struct _acl_list acl_list;
typedef struct _acl_access acl_access;
typedef struct _aclCheck_t aclCheck_t;
typedef struct _aio_result_t aio_result_t;
typedef struct _wordlist wordlist;
typedef struct _intlist intlist;
typedef struct _intrange intrange;
typedef struct _ushortlist ushortlist;
typedef struct _relist relist;
typedef struct _SquidConfig SquidConfig;
typedef struct _SquidConfig2 SquidConfig2;
typedef struct _close_handler close_handler;
typedef struct _dread_ctrl dread_ctrl;
typedef struct _dnsserver_t dnsserver_t;
typedef struct _dnsStatData dnsStatData;
typedef struct _dwrite_q dwrite_q;
typedef struct _ETag ETag;
typedef struct _fde fde;
typedef struct _fileMap fileMap;
typedef struct _fqdncache_entry fqdncache_entry;
typedef struct _fqdn_pending fqdn_pending;
typedef struct _HttpReply http_reply;
typedef struct _HttpStatusLine HttpStatusLine;
typedef struct _HttpHeaderFieldAttrs HttpHeaderFieldAttrs;
typedef struct _HttpHeaderFieldInfo HttpHeaderFieldInfo;
typedef struct _HttpHeader HttpHeader;
typedef struct _HttpHdrCc HttpHdrCc;
typedef struct _HttpHdrRangeSpec HttpHdrRangeSpec;
typedef struct _HttpHdrRange HttpHdrRange;
typedef struct _HttpHdrRangeIter HttpHdrRangeIter;
typedef struct _HttpHdrContRange HttpHdrContRange;
typedef struct _TimeOrTag TimeOrTag;
typedef struct _HttpHeaderEntry HttpHeaderEntry;
typedef struct _HttpHeaderFieldStat HttpHeaderFieldStat;
typedef struct _HttpHeaderStat HttpHeaderStat;
typedef struct _HttpBody HttpBody;
typedef struct _HttpReply HttpReply;
typedef struct _HttpStateData HttpStateData;
typedef struct _icpUdpData icpUdpData;
typedef struct _clientHttpRequest clientHttpRequest;
typedef struct _ConnStateData ConnStateData;
typedef struct _ipcache_addrs ipcache_addrs;
typedef struct _ipcache_entry ipcache_entry;
typedef struct _ip_pending ip_pending;
typedef struct _domain_ping domain_ping;
typedef struct _domain_type domain_type;
typedef struct _DynPool DynPool;
typedef struct _Packer Packer;
typedef struct _StoreDigestCBlock StoreDigestCBlock;
typedef struct _DigestFetchState DigestFetchState;
typedef struct _PeerDigest PeerDigest;
typedef struct _peer peer;
typedef struct _net_db_name net_db_name;
typedef struct _net_db_peer net_db_peer;
typedef struct _netdbEntry netdbEntry;
typedef struct _ping_data ping_data;
typedef struct _ps_state ps_state;
typedef struct _HierarchyLogEntry HierarchyLogEntry;
typedef struct _pingerEchoData pingerEchoData;
typedef struct _pingerReplyData pingerReplyData;
typedef struct _icp_common_t icp_common_t;
typedef struct _Meta_data Meta_data;
typedef struct _iostats iostats;
typedef struct _MemBuf MemBuf;
typedef struct _mem_node mem_node;
typedef struct _mem_hdr mem_hdr;
typedef struct _store_client store_client;
typedef struct _MemObject MemObject;
typedef struct _StoreEntry StoreEntry;
typedef struct _SwapDir SwapDir;
typedef struct _request_flags request_flags;
typedef struct _helper_flags helper_flags;
typedef struct _http_state_flags http_state_flags;
typedef struct _request_t request_t;
typedef struct _AccessLogEntry AccessLogEntry;
typedef struct _cachemgr_passwd cachemgr_passwd;
typedef struct _refresh_t refresh_t;
typedef struct _CommWriteStateData CommWriteStateData;
typedef struct _ErrorState ErrorState;
typedef struct _dlink_node dlink_node;
typedef struct _dlink_list dlink_list;
typedef struct _StatCounters StatCounters;
typedef struct _tlv tlv;
typedef struct _storeSwapLogData storeSwapLogData;
typedef struct _cacheSwap cacheSwap;
typedef struct _StatHist StatHist;
typedef struct _String String;
typedef struct _MemMeter MemMeter;
typedef struct _MemPoolMeter MemPoolMeter;
typedef struct _MemPool MemPool;
typedef struct _ClientInfo ClientInfo;
typedef struct _cd_guess_stats cd_guess_stats;
typedef struct _CacheDigest CacheDigest;
typedef struct _Version Version;
typedef struct _FwdState FwdState;
typedef struct _FwdServer FwdServer;
typedef struct _helper helper;
typedef struct _helper_server helper_server;
typedef struct _helper_request helper_request;
typedef struct _generic_cbdata generic_cbdata;
typedef struct _storeIOState storeIOState;

#if SQUID_SNMP
typedef variable_list *(oid_ParseFn) (variable_list *, snint *);
typedef struct _snmp_request_t snmp_request_t;
#endif

#if DELAY_POOLS
typedef struct _delayConfig delayConfig;
typedef struct _delaySpecSet delaySpecSet;
typedef struct _delaySpec delaySpec;
#endif

/* define AIOCB even without USE_ASYNC_IO */
typedef void AIOCB(int fd, void *, int aio_return, int aio_errno);
typedef void CWCB(int fd, char *, size_t size, int flag, void *data);
typedef void CNCB(int fd, int status, void *);

typedef void FREE(void *);
typedef void CBDUNL(void *, int);
typedef void FOCB(void *, int fd, int errcode);
typedef void EVH(void *);
typedef void PF(int, void *);
typedef void DRCB(int fd, const char *buf, int size, int errflag, void *data);
typedef void DWCB(int, int, size_t, void *);
typedef void FQDNH(const char *, void *);
typedef void IDCB(const char *ident, void *data);
typedef void IPH(const ipcache_addrs *, void *);
typedef void IRCB(peer *, peer_t, protocol_t, void *, void *data);
typedef void PSC(FwdServer *, void *);
typedef void RH(void *data, char *);
typedef void UH(void *data, wordlist *);
typedef int DEFER(int fd, void *data);

typedef void STIOCB(void *their_data, int errflag, storeIOState *);
typedef void STRCB(void *their_data, const char *buf, size_t len);

typedef void SIH(storeIOState *, void *);	/* swap in */
typedef int QS(const void *, const void *);	/* qsort */
typedef void STCB(void *, char *, ssize_t);	/* store callback */
typedef void STABH(void *);
typedef void ERCB(int fd, void *, size_t);
typedef void OBJH(StoreEntry *);
typedef void SIGHDLR(int sig);
typedef void STVLDCB(void *, int, int);
typedef void HLPCB(void *, char *buf);
typedef void HLPCMDOPTS(int *argc, char **argv);
typedef void IDNSCB(void *, rfc1035_rr *, int);

typedef void STINIT(SwapDir *);
typedef void STNEWFS(SwapDir *);
typedef storeIOState *STOBJOPEN(sfileno, mode_t, STIOCB *, void *);
typedef void STOBJCLOSE(storeIOState *);
typedef void STOBJREAD(storeIOState *, char *, size_t, off_t, STRCB *, void *);
typedef void STOBJWRITE(storeIOState *, char *, size_t, off_t, FREE *);
typedef void STOBJUNLINK(sfileno);
typedef void STOBJLOG(const SwapDir *, const StoreEntry *, int);
typedef void STLOGOPEN(SwapDir *);
typedef void STLOGCLOSE(SwapDir *);
typedef int STLOGCLEANOPEN(SwapDir *);
typedef void STLOGCLEANWRITE(const StoreEntry *, SwapDir *);

typedef double hbase_f(double);
typedef void StatHistBinDumper(StoreEntry *, int idx, double val, double size, int count);

/* append/vprintf's for Packer */
typedef void (*append_f) (void *, const char *buf, int size);
#if STDC_HEADERS
typedef void (*vprintf_f) (void *, const char *fmt, va_list args);
#else
typedef void (*vprintf_f) ();
#endif

/* MD5 cache keys */
typedef unsigned char cache_key;

/* context-based debugging, the actual type is subject to change */
typedef int Ctx;

/* in case we want to change it later */
typedef size_t mb_size_t;

/* iteration for HttpHdrRange */
typedef int HttpHdrRangePos;

/*iteration for headers; use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;

/* big mask for http headers */
typedef char HttpHeaderMask[8];

/* a common objPackInto interface; used by debugObj */
typedef void (*ObjPackMethod) (void *obj, Packer * p);

#if DELAY_POOLS
typedef unsigned int delay_id;
#endif

#if USE_HTCP
typedef struct _htcpReplyData htcpReplyData;
#endif
