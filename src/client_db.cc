/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Client Database */

#include "squid.h"
#include "base/PackableStream.h"
#include "base/RunnersRegistry.h"
#include "client_db.h"
#include "ClientInfo.h"
#include "event.h"
#include "format/Token.h"
#include "fqdncache.h"
#include "ip/Address.h"
#include "log/access_log.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"

#if SQUID_SNMP
#include "snmp_core.h"
#endif

#include <map>

static std::map<Ip::Address, ClientInfo::Pointer> client_table;

static ClientInfo *clientdbAdd(const Ip::Address &addr);

#if USE_DELAY_POOLS
static int max_clients = 32768;
#else
static int max_clients = 32;
#endif

static int cleanup_scheduled = 0;

ClientInfo::ClientInfo(const Ip::Address &ip) :
#if USE_DELAY_POOLS
    BandwidthBucket(0, 0, 0),
#endif
    addr(ip)
{
    debugs(77, 9, "ClientInfo constructed, this=" << static_cast<void*>(this));
}

static void
clientdbGC(void *)
{
    max_clients = statCounter.client_http.clients;

    int cleanup_removed = 0;
    for(auto itr = client_table.begin(); itr != client_table.end(); ) {
        const auto &c = itr->second;
        int age = squid_curtime - c->last_seen;

        auto skip = (c->n_established) ||
                    (age < 24 * 3600 && c->Http.n_requests > 100) ||
                    (age < 4 * 3600 && (c->Http.n_requests > 10 || c->Icp.n_requests > 10)) ||
                    (age < 5 * 60 && (c->Http.n_requests > 1 || c->Icp.n_requests > 1)) ||
                    (age < 60);
        if (skip)
            ++itr;
        else {
            itr = client_table.erase(itr);
            --statCounter.client_http.clients;
            ++cleanup_removed;
        }
    }
    debugs(49, 2, "removed " << cleanup_removed << " entries");

    if (!cleanup_scheduled) {
        ++cleanup_scheduled;
        eventAdd("client_db garbage collector", clientdbGC, NULL, 6 * 3600, 0);
    }
    max_clients = statCounter.client_http.clients * 3 / 2;
}

static ClientInfo *
clientdbAdd(const Ip::Address &addr)
{
    ClientInfo::Pointer c = new ClientInfo(addr);
    client_table[addr] = c;
    ++statCounter.client_http.clients;

    if ((statCounter.client_http.clients > max_clients) && cleanup_scheduled < 2) {
        ++cleanup_scheduled;
        eventAdd("client_db garbage collector", clientdbGC, NULL, 90, 0);
    }

    return c.getRaw();
}

static void
clientdbDump(StoreEntry *sentry)
{
    int icp_total = 0;
    int icp_hits = 0;
    int http_total = 0;
    int http_hits = 0;

    PackableStream out(*sentry);
    out << "Cache Clients:\n";

    for (const auto &itr : client_table) {
        const auto c = itr.second;
        out << "Address: " << c->addr << "\n";
        if (const auto name = fqdncache_gethostbyaddr(c->addr, 0))
            out << "Name:    " << name << "\n";

        out << "Currently established connections: " << c->n_established << "\n";
        out << "    ICP  Requests " << c->Icp.n_requests << "\n";

        for (LogTags_ot l = LOG_TAG_NONE; l < LOG_TYPE_MAX; ++l) {
            if (c->Icp.result_hist[l] == 0)
                continue;

            icp_total += c->Icp.result_hist[l];

            if (LOG_UDP_HIT == l)
                icp_hits += c->Icp.result_hist[l];

            out << "        " << LogTags(l).c_str() << " " << c->Icp.result_hist[l] << " " << Math::intPercent(c->Icp.result_hist[l], c->Icp.n_requests) << "%\n";
        }

        out << "    HTTP Requests: " << c->Http.n_requests << "\n";

        for (LogTags_ot l = LOG_TAG_NONE; l < LOG_TYPE_MAX; ++l) {
            if (c->Http.result_hist[l] == 0)
                continue;

            http_total += c->Http.result_hist[l];

            if (LogTags(l).isTcpHit())
                http_hits += c->Http.result_hist[l];

            out << "        " << LogTags(l).c_str() << " " << c->Http.result_hist[l] << " " << Math::intPercent(c->Http.result_hist[l], c->Http.n_requests) << "%\n";
        }

        out << "\n";
    }

    out << "TOTALS\n";
    out << "ICP : " << icp_total << " Queries, " << icp_hits << " Hits (" << Math::intPercent(icp_hits, icp_total) << "%)\n";
    out << "HTTP: " << http_total << " Requests, " << http_hits << " Hits (" << Math::intPercent(http_hits, http_total) << "%)\n";
    out.flush();
}

class ClientDbRr: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void useConfig() override {
        if (Config.onoff.client_db)
            Mgr::RegisterAction("client_list", "Cache Client List", clientdbDump, 0, 1);
    }
    virtual void finishShutdown() override {
        client_table.clear();
    }
};
RunnerRegistrationEntry(ClientDbRr);

/// \returns ClientInfo for given IP addr, or nullptr
ClientInfo *
clientdbGetInfo(const Ip::Address &addr)
{
    ClientInfo::Pointer c;
    if (Config.onoff.client_db) {
        auto result = client_table.find(addr);
        if (result == client_table.end())
            debugs(77, 2, "client DB does not contain " << addr);
        else
            c = result->second;
    }
    return c.getRaw();
}

void
clientdbUpdate(const Ip::Address &addr, const LogTags &ltype, AnyP::ProtocolType p, size_t size)
{
    if (!Config.onoff.client_db)
        return;

    auto c = clientdbGetInfo(addr);
    if (!c)
        c = clientdbAdd(addr);

    if (p == AnyP::PROTO_HTTP) {
        ++ c->Http.n_requests;
        ++ c->Http.result_hist[ltype.oldType];
        c->Http.kbytes_out += size;

        if (ltype.isTcpHit())
            c->Http.hit_kbytes_out += size;
    } else if (p == AnyP::PROTO_ICP) {
        ++ c->Icp.n_requests;
        ++ c->Icp.result_hist[ltype.oldType];
        c->Icp.kbytes_out += size;

        if (LOG_UDP_HIT == ltype.oldType)
            c->Icp.hit_kbytes_out += size;
    }

    c->last_seen = squid_curtime;
}

/**
 * This function tracks the number of currently established connections
 * for a client IP address.  When a connection is accepted, call this
 * with delta = 1.  When the connection is closed, call with delta =
 * -1.  To get the current value, simply call with delta = 0.
 */
int
clientdbEstablished(const Ip::Address &addr, int delta)
{
    if (!Config.onoff.client_db)
        return 0;

    auto c = clientdbGetInfo(addr);
    if (!c)
        c = clientdbAdd(addr);

    c->n_established += delta;

    return c->n_established;
}

#define CUTOFF_SECONDS 3600
int

clientdbCutoffDenied(const Ip::Address &addr)
{
    if (!Config.onoff.client_db)
        return 0;

    auto c = clientdbGetInfo(addr);
    if (!c)
        return 0;

    /*
     * If we are in a cutoff window, we don't send a reply
     */
    if (squid_curtime - c->cutoff.time < CUTOFF_SECONDS)
        return 1;

    /*
     * Calculate the percent of DENIED replies since the last
     * cutoff time.
     */
    auto NR = c->Icp.n_requests - c->cutoff.n_req;

    if (NR < 150)
        NR = 150;

    auto ND = c->Icp.result_hist[LOG_UDP_DENIED] - c->cutoff.n_denied;

    double p = 100.0 * ND / NR;

    if (p < 95.0)
        return 0;

    debugs(1, DBG_CRITICAL, "WARNING: Probable misconfigured neighbor at " << addr);

    debugs(1, DBG_CRITICAL, "WARNING: " << ND << " of the last " << NR <<
           " ICP replies are DENIED");

    debugs(1, DBG_CRITICAL, "WARNING: No replies will be sent for the next " <<
           CUTOFF_SECONDS << " seconds");

    c->cutoff.time = squid_curtime;

    c->cutoff.n_req = c->Icp.n_requests;

    c->cutoff.n_denied = c->Icp.result_hist[LOG_UDP_DENIED];

    return 1;
}

ClientInfo::~ClientInfo()
{
#if USE_DELAY_POOLS
    if (CommQuotaQueue *q = quotaQueue) {
        q->clientInfo = NULL;
        delete q; // invalidates cbdata, cancelling any pending kicks
    }
#endif

    debugs(77, 9, "ClientInfo destructed, this=" << static_cast<void*>(this));
}

#if SQUID_SNMP

const Ip::Address *
client_entry(const Ip::Address *current)
{
    if (client_table.empty())
        return nullptr;

    if (current) {
        auto itr = client_table.find(*current);
        ++itr;
        if (itr == client_table.end())
            return nullptr;
        return &(itr->first);
    }

    return &(client_table.begin()->first);
}

variable_list *
snmp_meshCtblFn(variable_list * Var, snint * ErrP)
{
    Ip::Address keyIp;

    *ErrP = SNMP_ERR_NOERROR;
    MemBuf tmp;
    debugs(49, 6, HERE << "Current : length=" << Var->name_length << ": " << snmpDebugOid(Var->name, Var->name_length, tmp));
    if (Var->name_length == 16) {
        oid2addr(&(Var->name[12]), keyIp, 4);
    } else if (Var->name_length == 28) {
        oid2addr(&(Var->name[12]), keyIp, 16);
    } else {
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return NULL;
    }

    debugs(49, 5, "[" << keyIp << "] requested!");
    const auto itr = client_table.find(keyIp);
    if (itr == client_table.end()) {
        debugs(49, 5, HERE << "not found.");
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return NULL;
    }
    const auto c = itr->second;

    variable_list *Answer = NULL;
    int aggr = 0;

    switch (Var->name[LEN_SQ_NET + 2]) {

    case MESH_CTBL_ADDR_TYPE: {
        int ival;
        ival = c->addr.isIPv4() ? INETADDRESSTYPE_IPV4 : INETADDRESSTYPE_IPV6 ;
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      ival, SMI_INTEGER);
    }
    break;

    case MESH_CTBL_ADDR: {
        Answer = snmp_var_new(Var->name, Var->name_length);
        // InetAddress doesn't have its own ASN.1 type,
        // like IpAddr does (SMI_IPADDRESS)
        // See: rfc4001.txt
        Answer->type = ASN_OCTET_STR;
        char client[MAX_IPSTRLEN];
        c->addr.toStr(client,MAX_IPSTRLEN);
        Answer->val_len = strlen(client);
        Answer->val.string =  (u_char *) xstrdup(client);
    }
    break;
    case MESH_CTBL_HTBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTREQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.n_requests,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTHITS:
        aggr = 0;

        for (LogTags_ot l = LOG_TAG_NONE; l < LOG_TYPE_MAX; ++l) {
            if (LogTags(l).isTcpHit())
                aggr += c->Http.result_hist[l];
        }

        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) aggr,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTHITBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.hit_kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPREQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.n_requests,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPHITS:
        aggr = c->Icp.result_hist[LOG_UDP_HIT];
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) aggr,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPHITBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.hit_kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        debugs(49, 5, "snmp_meshCtblFn: illegal column.");
        break;
    }

    return Answer;
}

#endif /*SQUID_SNMP */

