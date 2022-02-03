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
#include "clientdb/forward.h"
#include "clientdb/Cache.h"
#include "event.h"
#include "fqdncache.h"
#include "mem/PoolingAllocator.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StatCounters.h"

namespace ClientDb
{
std::map<Ip::Address, ClientInfo::Pointer> Cache;

/// number of garbage collection events scheduled
static int cleanup_scheduled = 0;

/// maximum number of HTTP clients to store info about
#if USE_DELAY_POOLS
static int max_clients = 32768;
#else
static int max_clients = 32;
#endif

} // namespace ClientDb

ClientInfo *
ClientDb::Add(const Ip::Address &addr)
{
    ClientInfo::Pointer c = new ClientInfo(addr);
    Cache[addr] = c;
    ++statCounter.client_http.clients;

    if ((statCounter.client_http.clients > max_clients) && cleanup_scheduled < 2) {
        ++cleanup_scheduled;
        eventAdd("client_db garbage collector", ClientDb::Prune, nullptr, 90, 0);
    }

    return c.getRaw();
}

void
ClientDb::Update(const Ip::Address &addr, const LogTags &ltype, AnyP::ProtocolType p, size_t size)
{
    if (!Config.onoff.client_db)
        return;

    auto c = Get(addr);
    if (!c)
        c = Add(addr);

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

ClientInfo *
ClientDb::Get(const Ip::Address &addr)
{
    ClientInfo::Pointer c;
    if (Config.onoff.client_db) {
        auto result = Cache.find(addr);
        if (result == Cache.end())
            debugs(77, 2, "client DB does not contain " << addr);
        else
            c = result->second;
    }
    return c.getRaw();
}

void
ClientDb::Prune(void *)
{
    --cleanup_scheduled;
    max_clients = statCounter.client_http.clients;

    int cleanup_removed = 0;
    for(auto itr = Cache.begin(); itr != Cache.end(); ) {
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
            itr = Cache.erase(itr);
            --statCounter.client_http.clients;
            ++cleanup_removed;
        }
    }
    debugs(49, 2, "removed " << cleanup_removed << " entries");

    if (!cleanup_scheduled) {
        ++cleanup_scheduled;
        eventAdd("client_db garbage collector", ClientDb::Prune, nullptr, 6 * 3600, 0);
    }
    max_clients = statCounter.client_http.clients * 3 / 2;
}

void
ClientDb::Report(StoreEntry *sentry)
{
    int icp_total = 0;
    int icp_hits = 0;
    int http_total = 0;
    int http_hits = 0;

    PackableStream out(*sentry);
    out << "Cache Clients:\n";

    for (const auto &itr : Cache) {
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

int
ClientDb::Established(const Ip::Address &addr, int delta)
{
    if (!Config.onoff.client_db)
        return 0;

    auto c = Get(addr);
    if (!c)
        c = Add(addr);

    c->n_established += delta;

    return c->n_established;
}

#define CUTOFF_SECONDS 3600
bool
ClientDb::IcpCutoffDenied(const Ip::Address &addr)
{
    if (!Config.onoff.client_db)
        return false;

    auto c = Get(addr);
    if (!c)
        return false;

    /*
     * If we are in a cutoff window, we don't send a reply
     */
    if (squid_curtime - c->cutoff.time < CUTOFF_SECONDS)
        return true;

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
        return false;
    debugs(1, DBG_CRITICAL, "WARNING: Probable misconfigured neighbor at " << addr <<
        Debug::Extra << ND << " of the last " << NR << " ICP replies are DENIED" <<
        Debug::Extra << "No replies will be sent for the next " << CUTOFF_SECONDS << " seconds");

    c->cutoff.time = squid_curtime;
    c->cutoff.n_req = c->Icp.n_requests;
    c->cutoff.n_denied = c->Icp.result_hist[LOG_UDP_DENIED];

    return true;
}

