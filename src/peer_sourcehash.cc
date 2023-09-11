/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#include "squid.h"
#include "CachePeer.h"
#include "CachePeers.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "peer_sourcehash.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "Store.h"

#include <cmath>

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/// sourcehash peers ordered by their sourcehash weight
static auto &
SourceHashPeers()
{
    static const auto hashPeers = new SelectedCachePeers();
    return *hashPeers;
}

static OBJH peerSourceHashCachemgr;
static void peerSourceHashRegisterWithCacheManager(void);

static int
peerSortWeight(const void *a, const void *b)
{
    const CachePeer *const *p1 = (const CachePeer *const *)a;
    const CachePeer *const *p2 = (const CachePeer *const *)b;
    return (*p1)->weight - (*p2)->weight;
}

void
peerSourceHashInit(void)
{
    int W = 0;
    double P_last, X_last, Xn;
    char *t;
    /* Clean up */

    SourceHashPeers().clear();
    /* find out which peers we have */

    RawCachePeers rawSourceHashPeers;
    for (const auto &p: CurrentCachePeers()) {
        const auto peer = p.get();

        if (!p->options.sourcehash)
            continue;

        assert(p->type == PEER_PARENT);

        if (p->weight == 0)
            continue;

        rawSourceHashPeers.push_back(peer);

        W += p->weight;
    }

    peerSourceHashRegisterWithCacheManager();

    if (rawSourceHashPeers.empty())
        return;

    /* calculate hashes and load factors */
    for (const auto &p: rawSourceHashPeers) {
        /* calculate this peers hash */
        p->sourcehash.hash = 0;

        for (t = p->name; *t != 0; ++t)
            p->sourcehash.hash += ROTATE_LEFT(p->sourcehash.hash, 19) + (unsigned int) *t;

        p->sourcehash.hash += p->sourcehash.hash * 0x62531965;

        p->sourcehash.hash = ROTATE_LEFT(p->sourcehash.hash, 21);

        /* and load factor */
        p->sourcehash.load_factor = ((double) p->weight) / (double) W;

        if (floor(p->sourcehash.load_factor * 1000.0) == 0.0)
            p->sourcehash.load_factor = 0.0;
    }

    /* Sort our list on weight */
    qsort(rawSourceHashPeers.data(), rawSourceHashPeers.size(), sizeof(decltype(rawSourceHashPeers)::value_type), peerSortWeight);

    /* Calculate the load factor multipliers X_k
     *
     * X_1 = pow ((K*p_1), (1/K))
     * X_k = ([K-k+1] * [P_k - P_{k-1}])/(X_1 * X_2 * ... * X_{k-1})
     * X_k += pow ((X_{k-1}, {K-k+1})
     * X_k = pow (X_k, {1/(K-k+1)})
     * simplified to have X_1 part of the loop
     */
    const auto K = rawSourceHashPeers.size();

    P_last = 0.0;       /* Empty P_0 */

    Xn = 1.0;           /* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;       /* Empty X_0, nullifies the first pow statement */

    for (size_t k = 1; k <= K; ++k) {
        double Kk1 = (double) (K - k + 1);
        const auto p = rawSourceHashPeers[k - 1];
        p->sourcehash.load_multiplier = (Kk1 * (p->sourcehash.load_factor - P_last)) / Xn;
        p->sourcehash.load_multiplier += pow(X_last, Kk1);
        p->sourcehash.load_multiplier = pow(p->sourcehash.load_multiplier, 1.0 / Kk1);
        Xn *= p->sourcehash.load_multiplier;
        X_last = p->sourcehash.load_multiplier;
        P_last = p->sourcehash.load_factor;
    }

    SourceHashPeers().assign(rawSourceHashPeers.begin(), rawSourceHashPeers.end());
}

static void
peerSourceHashRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("sourcehash", "peer sourcehash information",
                        peerSourceHashCachemgr, 0, 1);
}

CachePeer *
peerSourceHashSelectParent(PeerSelector *ps)
{
    const char *c;
    CachePeer *p = nullptr;
    unsigned int user_hash = 0;
    unsigned int combined_hash;
    double score;
    double high_score = 0;
    const char *key = nullptr;
    char ntoabuf[MAX_IPSTRLEN];

    if (SourceHashPeers().empty())
        return nullptr;

    assert(ps);
    HttpRequest *request = ps->request;

    key = request->client_addr.toStr(ntoabuf, sizeof(ntoabuf));

    /* calculate hash key */
    debugs(39, 2, "peerSourceHashSelectParent: Calculating hash for " << key);

    for (c = key; *c != 0; ++c)
        user_hash += ROTATE_LEFT(user_hash, 19) + *c;

    /* select CachePeer */
    for (const auto &tp: SourceHashPeers()) {
        if (!tp)
            continue; // peer gone

        combined_hash = (user_hash ^ tp->sourcehash.hash);
        combined_hash += combined_hash * 0x62531965;
        combined_hash = ROTATE_LEFT(combined_hash, 21);
        score = combined_hash * tp->sourcehash.load_multiplier;
        debugs(39, 3, *tp << " combined_hash " << combined_hash  <<
               " score " << std::setprecision(0) << score);

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
peerSourceHashCachemgr(StoreEntry * sentry)
{
    int sumfetches = 0;
    storeAppendPrintf(sentry, "%24s %10s %10s %10s %10s\n",
                      "Hostname",
                      "Hash",
                      "Multiplier",
                      "Factor",
                      "Actual");

    for (const auto &p: SourceHashPeers()) {
        if (!p)
            continue;
        sumfetches += p->stats.fetches;
    }

    for (const auto &p: SourceHashPeers()) {
        if (!p)
            continue;
        storeAppendPrintf(sentry, "%24s %10x %10f %10f %10f\n",
                          p->name, p->sourcehash.hash,
                          p->sourcehash.load_multiplier,
                          p->sourcehash.load_factor,
                          sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }
}

