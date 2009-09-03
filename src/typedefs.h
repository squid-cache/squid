
/*
 * $Id$
 *
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

#include "squid.h"

#ifndef SQUID_TYPEDEFS_H
#define SQUID_TYPEDEFS_H

typedef signed int sfileno;
typedef signed int sdirno;

typedef struct {
    size_t bytes;
    size_t kb;
} kb_t;

//UNUSED		typedef struct _acl_time_data acl_time_data;
//UNUSED		typedef struct _acl_name_list acl_name_list;
//UNUSED		typedef struct _acl_deny_info_list acl_deny_info_list;
//UNUSED		typedef class AuthUser auth_user_t;


/// \ingroup AuthAPI
/// \deprecated Use AuthUserHashPointer instead.
typedef struct AuthUserHashPointer auth_user_hash_pointer;

/// \ingroup AuthAPI
/// \deprecated Use AuthUserIP instead.
typedef struct AuthUserIP auth_user_ip_t;

/* temporary: once Config is fully hidden, this shouldn't be needed */
#include "Array.h"

class AuthConfig;
typedef Vector<AuthConfig *> authConfig;

//UNUSED		typedef struct _acl_snmp_comm acl_snmp_comm;
//UNUSED		typedef class ACLList acl_list;
//UNUSED		typedef struct _acl_address acl_address;
//UNUSED		typedef struct _acl_tos acl_tos;
//UNUSED		typedef struct _acl_size_t acl_size_t;
//UNUSED		class ACLChecklist;
//UNUSED		typedef struct _ushortlist ushortlist;
//UNUSED		typedef struct _relist relist;

struct http_port_list;
struct https_port_list;

//UNUSED	typedef struct _SquidConfig SquidConfig;
//UNUSED	typedef struct _SquidConfig2 SquidConfig2;

typedef struct _close_handler close_handler;

typedef struct _dread_ctrl dread_ctrl;

typedef struct _dwrite_q dwrite_q;

typedef struct _ETag ETag;

//UNUSED		class fde;

typedef struct _fileMap fileMap;

typedef struct _HttpHeaderFieldAttrs HttpHeaderFieldAttrs;

//UNUSED		class HttpHeaderFieldInfo;
//UNUSED		class HttpHeader;
//UNUSED		class HttpHdrCc;

typedef struct _TimeOrTag TimeOrTag;

//UNUSED		class HttpHeaderFieldStat;

typedef struct _HttpHeaderStat HttpHeaderStat;

typedef struct _HttpBody HttpBody;

//UNUSED		class HttpReply;

typedef struct _ConnCloseHelperData ConnCloseHelperData;

typedef struct _ipcache_addrs ipcache_addrs;

typedef struct _domain_ping domain_ping;

typedef struct _domain_type domain_type;

typedef struct _DynPool DynPool;

typedef struct _DigestFetchState DigestFetchState;

//UNUSED		class PeerDigest;

//UNUSED typedef struct _peer peer;

typedef struct _net_db_name net_db_name;

typedef struct _net_db_peer net_db_peer;

typedef struct _netdbEntry netdbEntry;

typedef struct _icp_common_t icp_common_t;

typedef struct _Meta_data Meta_data;

typedef struct _iostats iostats;

//UNUSED		class MemBuf;

//UNUSED		class store_client;

//UNUSED		class SwapDir;

typedef struct _http_state_flags http_state_flags;

typedef struct _header_mangler header_mangler;

typedef struct _body_size body_size;

//UNUSED		class HttpRequest;

typedef struct _cachemgr_passwd cachemgr_passwd;

typedef struct _refresh_t refresh_t;

typedef struct _CommWriteStateData CommWriteStateData;

typedef struct _StatCounters StatCounters;

/// \todo DROP: deprecated and no longer used.
typedef struct _storeSwapLogData storeSwapLogData;

typedef struct _StatHist StatHist;

typedef struct _cd_guess_stats cd_guess_stats;

typedef struct _CacheDigest CacheDigest;

typedef struct _Version Version;

typedef struct _link_list link_list;

typedef struct _Logfile Logfile;

typedef struct _logformat logformat;

typedef struct _customlog customlog;

#if SQUID_SNMP
typedef variable_list *(oid_ParseFn) (variable_list *, snint *);

typedef struct _snmp_request_t snmp_request_t;
#endif

typedef void FREE(void *);
typedef void CBDUNL(void *);
typedef void FOCB(void *, int fd, int errcode);
typedef void PF(int, void *);

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);	/* disk write CB */
typedef void DOCB(int, int errflag, void *data);	/* disk open CB */
typedef void DCCB(int, int errflag, void *data);	/* disk close CB */
typedef void DUCB(int errflag, void *data);	/* disk unlink CB */
typedef void DTCB(int errflag, void *data);	/* disk trunc CB */

class DnsLookupDetails;
typedef void FQDNH(const char *, const DnsLookupDetails &details, void *);
typedef void IDCB(const char *ident, void *data);
typedef void IPH(const ipcache_addrs *, const DnsLookupDetails &details, void *);
typedef void IRCB(struct peer *, peer_t, protocol_t, void *, void *data);

class FwdServer;
typedef void PSC(FwdServer *, void *);
typedef void RH(void *data, char *);
/* in wordlist.h */

class wordlist;
typedef void UH(void *data, wordlist *);
typedef int READ_HANDLER(int, char *, int);
typedef int WRITE_HANDLER(int, const char *, int);

typedef int QS(const void *, const void *);	/* qsort */
typedef void STABH(void *);
typedef void ERCB(int fd, void *, size_t);
class StoreEntry;
typedef void OBJH(StoreEntry *);
typedef void SIGHDLR(int sig);
typedef void STVLDCB(void *, int, int);
typedef void HLPCB(void *, char *buf);
typedef int HLPSAVAIL(void *);
typedef void HLPSONEQ(void *);
typedef void HLPCMDOPTS(int *argc, char **argv);
typedef void IDNSCB(void *, rfc1035_rr *, int, const char *);

typedef double hbase_f(double);
typedef void StatHistBinDumper(StoreEntry *, int idx, double val, double size, int count);

/* MD5 cache keys */
typedef unsigned char cache_key;

/* in case we want to change it later */
typedef ssize_t mb_size_t;

typedef int STDIRSELECT(const StoreEntry *);
#endif /* SQUID_TYPEDEFS_H */
