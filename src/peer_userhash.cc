/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer user hash based selection */

#include "squid.h"

#if USE_AUTH

#include "auth/UserRequest.h"
#include "CachePeer.h"
#include "CachePeers.h"
#include "globals.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "peer_userhash.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "Store.h"

#include <cmath>

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/// userhash peers ordered by their userhash weight
static auto &
UserHashPeers()
{
    static const auto hashPeers = new SelectedCachePeers();
    return *hashPeers;
}

static OBJH peerUserHashCachemgr;
static void peerUserHashRegisterWithCacheManager(void);

static int
peerSortWeight(const void *a, const void *b)
{
    const CachePeer *const *p1 = (const CachePeer *const *)a;
    const CachePeer *const *p2 = (const CachePeer *const *)b;
    return (*p1)->weight - (*p2)->weight;
}

void
peerUserHashInit(void)
{
    int W = 0;
    double P_last, X_last, Xn;
    char *t;
    /* Clean up */

    UserHashPeers().clear();
    /* find out which peers we have */

    peerUserHashRegisterWithCacheManager();

    RawCachePeers rawUserHashPeers;
    for (const auto &p: CurrentCachePeers()) {
        const auto peer = p.get();

        if (!p->options.userhash)
            continue;

        assert(p->type == PEER_PARENT);

        if (p->weight == 0)
            continue;

        rawUserHashPeers.push_back(peer);

        W += p->weight;
    }

    if (rawUserHashPeers.empty())
        return;

    /* calculate hashes and load factors */
    for (const auto &p: rawUserHashPeers) {
        /* calculate this peers hash */
        p->userhash.hash = 0;

        for (t = p->name; *t != 0; ++t)
            p->userhash.hash += ROTATE_LEFT(p->userhash.hash, 19) + (unsigned int) *t;

        p->userhash.hash += p->userhash.hash * 0x62531965;

        p->userhash.hash = ROTATE_LEFT(p->userhash.hash, 21);

        /* and load factor */
        p->userhash.load_factor = ((double) p->weight) / (double) W;

        if (floor(p->userhash.load_factor * 1000.0) == 0.0)
            p->userhash.load_factor = 0.0;
    }

    /* Sort our list on weight */
    qsort(rawUserHashPeers.data(), rawUserHashPeers.size(), sizeof(decltype(rawUserHashPeers)::value_type), peerSortWeight);

    /* Calculate the load factor multipliers X_k
     *
     * X_1 = pow ((K*p_1), (1/K))
     * X_k = ([K-k+1] * [P_k - P_{k-1}])/(X_1 * X_2 * ... * X_{k-1})
     * X_k += pow ((X_{k-1}, {K-k+1})
     * X_k = pow (X_k, {1/(K-k+1)})
     * simplified to have X_1 part of the loop
     */
    const auto K = rawUserHashPeers.size();

    P_last = 0.0;       /* Empty P_0 */

    Xn = 1.0;           /* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;       /* Empty X_0, nullifies the first pow statement */

    for (size_t k = 1; k <= K; ++k) {
        double Kk1 = (double) (K - k + 1);
        const auto p = rawUserHashPeers[k - 1];
        p->userhash.load_multiplier = (Kk1 * (p->userhash.load_factor - P_last)) / Xn;
        p->userhash.load_multiplier += pow(X_last, Kk1);
        p->userhash.load_multiplier = pow(p->userhash.load_multiplier, 1.0 / Kk1);
        Xn *= p->userhash.load_multiplier;
        X_last = p->userhash.load_multiplier;
        P_last = p->userhash.load_factor;
    }

    UserHashPeers().assign(rawUserHashPeers.begin(), rawUserHashPeers.end());
}

static void
peerUserHashRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("userhash", "peer userhash information", peerUserHashCachemgr,
                        0, 1);
}

CachePeer *
peerUserHashSelectParent(PeerSelector *ps)
{
    const char *c;
    CachePeer *p = nullptr;
    unsigned int user_hash = 0;
    unsigned int combined_hash;
    double score;
    double high_score = 0;
    const char *key = nullptr;

    if (UserHashPeers().empty())
        return nullptr;

    assert(ps);
    HttpRequest *request = ps->request;

    if (request->auth_user_request != nullptr)
        key = request->auth_user_request->username();

    if (!key)
        return nullptr;

    /* calculate hash key */
    debugs(39, 2, "peerUserHashSelectParent: Calculating hash for " << key);

    for (c = key; *c != 0; ++c)
        user_hash += ROTATE_LEFT(user_hash, 19) + *c;

    /* select CachePeer */
    for (const auto &tp: UserHashPeers()) {
        if (!tp)
            continue; // peer gone

        combined_hash = (user_hash ^ tp->userhash.hash);
        combined_hash += combined_hash * 0x62531965;
        combined_hash = ROTATE_LEFT(combined_hash, 21);
        score = combined_hash * tp->userhash.load_multiplier;
        debugs(39, 3, *tp << " combined_hash " << combined_hash <<
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
peerUserHashCachemgr(StoreEntry * sentry)
{
    int sumfetches = 0;
    storeAppendPrintf(sentry, "%24s %10s %10s %10s %10s\n",
                      "Hostname",
                      "Hash",
                      "Multiplier",
                      "Factor",
                      "Actual");

    for (const auto &p: UserHashPeers()) {
        if (!p)
            continue;
        sumfetches += p->stats.fetches;
    }

    for (const auto &p: UserHashPeers()) {
        if (!p)
            continue;
        storeAppendPrintf(sentry, "%24s %10x %10f %10f %10f\n",
                          p->name, p->userhash.hash,
                          p->userhash.load_multiplier,
                          p->userhash.load_factor,
                          sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }
}

#endif /* USE_AUTH */

