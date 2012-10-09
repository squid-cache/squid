#ifndef SQUID_SQUIDCONFIG_H_
#define SQUID_SQUIDCONFIG_H_
/*
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

#include "acl/AclAddress.h"
#include "ClientDelayConfig.h"
#include "DelayConfig.h"
#include "HelperChildConfig.h"
#include "HttpHeaderTools.h"
#include "icmp/IcmpConfig.h"
#include "ip/Address.h"
#include "RefCount.h"
#include "YesNoNone.h"

#if USE_SSL
#include <openssl/ssl.h>
class sslproxy_cert_sign;
class sslproxy_cert_adapt;
#endif

class acl_access;
class AclSizeLimit;
class AclDenyInfoList;
namespace Mgr
{
class ActionPasswordList;
} // namespace Mgr
class CustomLog;
class CpuAffinityMap;
class external_acl;
class HeaderManglers;
class RefreshPattern;
class RemovalPolicySettings;
class SwapDir;

namespace AnyP
{
class PortCfg;
}

/// the representation of the configuration. POD.
class SquidConfig
{
public:
    struct {
        /* These should be for the Store::Root instance.
        * this needs pluggable parsing to be done smoothly.
        */
        int highWaterMark;
        int lowWaterMark;
    } Swap;

    YesNoNone memShared; ///< whether the memory cache is shared among workers
    size_t memMaxSize;

    struct {
        int64_t min;
        int pct;
        int64_t max;
    } quickAbort;
    int64_t readAheadGap;
    RemovalPolicySettings *replPolicy;
    RemovalPolicySettings *memPolicy;
#if USE_HTTP_VIOLATIONS
    time_t negativeTtl;
#endif
    time_t maxStale;
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    time_t backgroundPingRate;

    struct {
        time_t read;
        time_t write;
        time_t lifetime;
        time_t connect;
        time_t forward;
        time_t peer_connect;
        time_t request;
        time_t clientIdlePconn;
        time_t serverIdlePconn;
        time_t siteSelect;
        time_t deadPeer;
        int icp_query;      /* msec */
        int icp_query_max;  /* msec */
        int icp_query_min;  /* msec */
        int mcast_icp_query;    /* msec */

#if !USE_DNSHELPER
        time_msec_t idns_retransmit;
        time_msec_t idns_query;
#endif

    } Timeout;
    size_t maxRequestHeaderSize;
    int64_t maxRequestBodySize;
    int64_t maxChunkedRequestBodySize;
    size_t maxRequestBufferSize;
    size_t maxReplyHeaderSize;
    AclSizeLimit *ReplyBodySize;

    struct {
        unsigned short icp;
#if USE_HTCP

        unsigned short htcp;
#endif
#if SQUID_SNMP

        unsigned short snmp;
#endif
    } Port;

    struct {
        AnyP::PortCfg *http;
#if USE_SSL
        AnyP::PortCfg *https;
#endif
    } Sockaddr;
#if SQUID_SNMP

    struct {
        char *configFile;
        char *agentInfo;
    } Snmp;
#endif
#if USE_WCCP

    struct {
        Ip::Address router;
        Ip::Address address;
        int version;
    } Wccp;
#endif
#if USE_WCCPv2

    struct {
        Ip::Address_list *router;
        Ip::Address address;
        int forwarding_method;
        int return_method;
        int assignment_method;
        int weight;
        int rebuildwait;
        void *info;
    } Wccp2;
#endif

#if USE_ICMP
    IcmpConfig pinger;
#endif

    char *as_whois_server;

    struct {
        char *store;
        char *swap;
        CustomLog *accesslogs;
#if ICAP_CLIENT
        CustomLog *icaplogs;
#endif
        int rotateNumber;
    } Log;
    char *adminEmail;
    char *EmailFrom;
    char *EmailProgram;
    char *effectiveUser;
    char *visible_appname_string;
    char *effectiveGroup;

    struct {
#if USE_DNSHELPER
        char *dnsserver;
#endif

        wordlist *redirect;
#if USE_UNLINKD

        char *unlinkd;
#endif

        char *diskd;
#if USE_SSL

        char *ssl_password;
#endif

    } Program;
#if USE_DNSHELPER
    HelperChildConfig dnsChildren;
#endif

    HelperChildConfig redirectChildren;
    time_t authenticateGCInterval;
    time_t authenticateTTL;
    time_t authenticateIpTTL;

    struct {
        char *surrogate_id;
    } Accel;
    char *appendDomain;
    size_t appendDomainLen;
    char *pidFilename;
    char *netdbFilename;
    char *mimeTablePathname;
    char *etcHostsPath;
    char *visibleHostname;
    char *uniqueHostname;
    wordlist *hostnameAliases;
    char *errHtmlText;

    struct {
        char *host;
        char *file;
        time_t period;
        unsigned short port;
    } Announce;

    struct {

        Ip::Address udp_incoming;
        Ip::Address udp_outgoing;
#if SQUID_SNMP
        Ip::Address snmp_incoming;
        Ip::Address snmp_outgoing;
#endif
        /* FIXME INET6 : this should really be a CIDR value */
        Ip::Address client_netmask;
    } Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_nameservers;
    CachePeer *peers;
    int npeers;

    struct {
        int size;
        int low;
        int high;
    } ipcache;

    struct {
        int size;
    } fqdncache;
    int minDirectHops;
    int minDirectRtt;
    Mgr::ActionPasswordList *passwd_list;

    struct {
        int objectsPerBucket;
        int64_t avgObjectSize;
        int64_t maxObjectSize;
        int64_t minObjectSize;
        size_t maxInMemObjSize;
    } Store;

    struct {
        int high;
        int low;
        time_t period;
    } Netdb;

    struct {
        int log_udp;
        int res_defnames;
        int anonymizer;
        int client_db;
        int query_icmp;
        int icp_hit_stale;
        int buffered_logs;
        int common_log;
        int log_mime_hdrs;
        int log_fqdn;
        int announce;
        int mem_pools;
        int test_reachability;
        int half_closed_clients;
        int refresh_all_ims;
#if USE_HTTP_VIOLATIONS

        int reload_into_ims;
#endif

        int offline;
        int redir_rewrites_host;
        int prefer_direct;
        int nonhierarchical_direct;
        int strip_query_terms;
        int redirector_bypass;
        int ignore_unknown_nameservers;
        int client_pconns;
        int server_pconns;
        int error_pconns;
#if USE_CACHE_DIGESTS

        int digest_generation;
#endif

        int ie_refresh;
        int vary_ignore_expire;
        int pipeline_prefetch;
        int surrogate_is_remote;
        int request_entities;
        int detect_broken_server_pconns;
        int balance_on_multiple_ip;
        int relaxed_header_parser;
        int check_hostnames;
        int allow_underscore;
        int via;
        int emailErrData;
        int httpd_suppress_version_string;
        int global_internal_static;

#if FOLLOW_X_FORWARDED_FOR
        int acl_uses_indirect_client;
        int delay_pool_uses_indirect_client;
        int log_uses_indirect_client;
#if LINUX_NETFILTER
        int tproxy_uses_indirect_client;
#endif
#endif /* FOLLOW_X_FORWARDED_FOR */

        int WIN32_IpAddrChangeMonitor;
        int memory_cache_first;
        int memory_cache_disk;
        int hostStrictVerify;
        int client_dst_passthru;
    } onoff;

    int forward_max_tries;
    int connect_retries;

    class ACL *aclList;

    struct {
        acl_access *http;
        acl_access *adapted_http;
        acl_access *icp;
        acl_access *miss;
        acl_access *NeverDirect;
        acl_access *AlwaysDirect;
        acl_access *ASlists;
        acl_access *noCache;
        acl_access *log;
#if SQUID_SNMP

        acl_access *snmp;
#endif
#if USE_HTTP_VIOLATIONS
        acl_access *brokenPosts;
#endif
        acl_access *redirector;
        acl_access *reply;
        AclAddress *outgoing_address;
#if USE_HTCP

        acl_access *htcp;
        acl_access *htcp_clr;
#endif

#if USE_SSL
        acl_access *ssl_bump;
#endif
#if FOLLOW_X_FORWARDED_FOR
        acl_access *followXFF;
#endif /* FOLLOW_X_FORWARDED_FOR */

#if ICAP_CLIENT
        acl_access* icap;
#endif
    } accessList;
    AclDenyInfoList *denyInfoList;

    struct {
        size_t list_width;
        int list_wrap;
        char *anon_user;
        int passive;
        int epsv_all;
        int epsv;
        int eprt;
        int sanitycheck;
        int telnet;
    } Ftp;
    RefreshPattern *Refresh;

    struct _cacheSwap {
        RefCount<SwapDir> *swapDirs;
        int n_allocated;
        int n_configured;
        /// number of disk processes required to support all cache_dirs
        int n_strands;
    } cacheSwap;
    /*
     * I'm sick of having to keep doing this ..
     */
#define INDEXSD(i)   (Config.cacheSwap.swapDirs[(i)].getRaw())

    struct {
        char *directory;
        int use_short_names;
    } icons;
    char *errorDirectory;
#if USE_ERR_LOCALES
    char *errorDefaultLanguage;
    int errorLogMissingLanguages;
#endif
    char *errorStylesheet;

    struct {
        int onerror;
    } retry;

    struct {
        int64_t limit;
    } MemPools;
#if USE_DELAY_POOLS

    DelayConfig Delay;
    ClientDelayConfig ClientDelay;
#endif

    struct {
        struct {
            int average;
            int min_poll;
        } dns, udp, tcp;
    } comm_incoming;
    int max_open_disk_fds;
    int uri_whitespace;
    AclSizeLimit *rangeOffsetLimit;
#if MULTICAST_MISS_STREAM

    struct {

        Ip::Address addr;
        int ttl;
        unsigned short port;
        char *encode_key;
    } mcast_miss;
#endif

    /// request_header_access and request_header_replace
    HeaderManglers *request_header_access;
    /// reply_header_access and reply_header_replace
    HeaderManglers *reply_header_access;
    ///request_header_add access list
    HeaderWithAclList *request_header_add;
    char *coredump_dir;
    char *chroot_dir;
#if USE_CACHE_DIGESTS

    struct {
        int bits_per_entry;
        time_t rebuild_period;
        time_t rewrite_period;
        size_t swapout_chunk_size;
        int rebuild_chunk_percentage;
    } digest;
#endif
#if USE_SSL

    struct {
        int unclean_shutdown;
        char *ssl_engine;
    } SSL;
#endif

    wordlist *ext_methods;

    struct {
        int high_rptm;
        int high_pf;
        size_t high_memory;
    } warnings;
    char *store_dir_select_algorithm;
    int sleep_after_fork;   /* microseconds */
    time_t minimum_expiry_time; /* seconds */
    external_acl *externalAclHelperList;

#if USE_SSL

    struct {
        char *cert;
        char *key;
        int version;
        char *options;
        char *cipher;
        char *cafile;
        char *capath;
        char *crlfile;
        char *flags;
        acl_access *cert_error;
        SSL_CTX *sslContext;
        sslproxy_cert_sign *cert_sign;
        sslproxy_cert_adapt *cert_adapt;
    } ssl_client;
#endif

    char *accept_filter;
    int umask;
    int max_filedescriptors;
    int workers;
    CpuAffinityMap *cpuAffinityMap;

#if USE_LOADABLE_MODULES
    wordlist *loadable_module_names;
#endif

    int client_ip_max_connections;

    struct {
        int v4_first;       ///< Place IPv4 first in the order of DNS results.
        ssize_t packet_max; ///< maximum size EDNS advertised for DNS replies.
    } dns;

};

extern SquidConfig Config;

class SquidConfig2
{
public:
    struct {
        int enable_purge;
        int mangle_request_headers;
    } onoff;
    uid_t effectiveUserID;
    gid_t effectiveGroupID;
};

extern SquidConfig2 Config2;

#endif /* SQUID_SQUIDCONFIG_H_ */
