/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Cache Array Routing Protocol */

#include "squid.h"
#include "CachePeer.h"
#include "CachePeers.h"
#include "carp.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "Store.h"

#include <cmath>

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/// CARP cache_peers ordered by their CARP weight
static SelectedCachePeers TheCarpPeers;

static OBJH carpCachemgr;

static int
peerSortWeight(const void *a, const void *b)
{
    const CachePeer *const *p1 = (const CachePeer *const *)a;
    const CachePeer *const *p2 = (const CachePeer *const *)b;
    return (*p1)->weight - (*p2)->weight;
}

static void
carpRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("carp", "CARP information", carpCachemgr, 0, 1);
}

void
carpInit(void)
{
    int W = 0;
    double P_last, X_last, Xn;
    char *t;
    /* Clean up */

    TheCarpPeers.clear();

    /* initialize cache manager before we have a chance to leave the execution path */
    carpRegisterWithCacheManager();

    /* find out which peers we have */

    RawCachePeers rawCarpPeers;
    for (auto p = Config.peers; p; p = p->next) {
        if (!cbdataReferenceValid(p))
            continue;

        if (!p->options.carp)
            continue;

        assert(p->type == PEER_PARENT);

        if (p->weight == 0)
            continue;

        rawCarpPeers.push_back(p);

        W += p->weight;
    }

    if (rawCarpPeers.empty())
        return;

    /* calculate hashes and load factors */
    for (const auto p: rawCarpPeers) {
        /* calculate this peers hash */
        p->carp.hash = 0;

        for (t = p->name; *t != 0; ++t)
            p->carp.hash += ROTATE_LEFT(p->carp.hash, 19) + (unsigned int) *t;

        p->carp.hash += p->carp.hash * 0x62531965;

        p->carp.hash = ROTATE_LEFT(p->carp.hash, 21);

        /* and load factor */
        p->carp.load_factor = ((double) p->weight) / (double) W;

        if (floor(p->carp.load_factor * 1000.0) == 0.0)
            p->carp.load_factor = 0.0;
    }

    /* Sort our list on weight */
    qsort(rawCarpPeers.data(), rawCarpPeers.size(), sizeof(decltype(rawCarpPeers)::value_type), peerSortWeight);

    /* Calculate the load factor multipliers X_k
     *
     * X_1 = pow ((K*p_1), (1/K))
     * X_k = ([K-k+1] * [P_k - P_{k-1}])/(X_1 * X_2 * ... * X_{k-1})
     * X_k += pow ((X_{k-1}, {K-k+1})
     * X_k = pow (X_k, {1/(K-k+1)})
     * simplified to have X_1 part of the loop
     */
    const auto K = rawCarpPeers.size();

    P_last = 0.0;       /* Empty P_0 */

    Xn = 1.0;           /* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;       /* Empty X_0, nullifies the first pow statement */

    for (size_t k = 1; k <= K; ++k) {
        double Kk1 = (double) (K - k + 1);
        const auto p = rawCarpPeers[k - 1];
        p->carp.load_multiplier = (Kk1 * (p->carp.load_factor - P_last)) / Xn;
        p->carp.load_multiplier += pow(X_last, Kk1);
        p->carp.load_multiplier = pow(p->carp.load_multiplier, 1.0 / Kk1);
        Xn *= p->carp.load_multiplier;
        X_last = p->carp.load_multiplier;
        P_last = p->carp.load_factor;
    }

    TheCarpPeers.assign(rawCarpPeers.begin(), rawCarpPeers.end());
}

CachePeer *
carpSelectParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    CachePeer *p = nullptr;
    unsigned int user_hash = 0;
    unsigned int combined_hash;
    double score;
    double high_score = 0;

    if (TheCarpPeers.empty())
        return nullptr;

    /* calculate hash key */
    debugs(39, 2, "carpSelectParent: Calculating hash for " << request->effectiveRequestUri());

    /* select CachePeer */
    for (const auto &tp: TheCarpPeers) {
        if (!tp)
            continue; // peer gone

        SBuf key;
        if (tp->options.carp_key.set) {
            // this code follows URI syntax pattern.
            // corner cases should use the full effective request URI
            if (tp->options.carp_key.scheme) {
                key.append(request->url.getScheme().image());
                if (key.length()) //if the scheme is not empty
                    key.append("://");
            }
            if (tp->options.carp_key.host) {
                key.append(request->url.host());
            }
            if (tp->options.carp_key.port) {
                key.appendf(":%hu", request->url.port().value_or(0));
            }
            if (tp->options.carp_key.path) {
                // XXX: fix when path and query are separate
                key.append(request->url.path().substr(0,request->url.path().find('?'))); // 0..N
            }
            if (tp->options.carp_key.params) {
                // XXX: fix when path and query are separate
                SBuf::size_type pos;
                if ((pos=request->url.path().find('?')) != SBuf::npos)
                    key.append(request->url.path().substr(pos)); // N..npos
            }
        }
        // if the url-based key is empty, e.g. because the user is
        // asking to balance on the path but the request doesn't supply any,
        // then fall back to the effective request URI

        if (key.isEmpty())
            key=request->effectiveRequestUri();

        for (const char *c = key.rawContent(), *e=key.rawContent()+key.length(); c < e; ++c)
            user_hash += ROTATE_LEFT(user_hash, 19) + *c;
        combined_hash = (user_hash ^ tp->carp.hash);
        combined_hash += combined_hash * 0x62531965;
        combined_hash = ROTATE_LEFT(combined_hash, 21);
        score = combined_hash * tp->carp.load_multiplier;
        debugs(39, 3, *tp << " key=" << key << " combined_hash=" << combined_hash  <<
               " score=" << std::setprecision(0) << score);

        if ((score > high_score) && peerHTTPOkay(tp.get(), ps)) {
            p = tp.get();
            high_score = score;
        }
    }

    if (p)
        debugs(39, 2, "selected " << *p);

    return p;
}

static void
carpCachemgr(StoreEntry * sentry)
{
    int sumfetches = 0;
    storeAppendPrintf(sentry, "%24s %10s %10s %10s %10s\n",
                      "Hostname",
                      "Hash",
                      "Multiplier",
                      "Factor",
                      "Actual");

    for (const auto &p: TheCarpPeers) {
        if (!p)
            continue;
        sumfetches += p->stats.fetches;
    }

    for (const auto &p: TheCarpPeers) {
        if (!p)
            continue;
        storeAppendPrintf(sentry, "%24s %10x %10f %10f %10f\n",
                          p->name, p->carp.hash,
                          p->carp.load_multiplier,
                          p->carp.load_factor,
                          sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }
}

