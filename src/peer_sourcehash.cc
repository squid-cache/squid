/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#include "squid.h"
#include "CachePeer.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "SquidConfig.h"
#include "Store.h"

#include <cmath>

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static int n_sourcehash_peers = 0;
static CachePeer **sourcehash_peers = NULL;
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
    int K;
    int k;
    double P_last, X_last, Xn;
    CachePeer *p;
    CachePeer **P;
    char *t;
    /* Clean up */

    for (k = 0; k < n_sourcehash_peers; ++k) {
        cbdataReferenceDone(sourcehash_peers[k]);
    }

    safe_free(sourcehash_peers);
    n_sourcehash_peers = 0;
    /* find out which peers we have */

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.sourcehash)
            continue;

        assert(p->type == PEER_PARENT);

        if (p->weight == 0)
            continue;

        ++n_sourcehash_peers;

        W += p->weight;
    }

    peerSourceHashRegisterWithCacheManager();

    if (n_sourcehash_peers == 0)
        return;

    sourcehash_peers = (CachePeer **)xcalloc(n_sourcehash_peers, sizeof(*sourcehash_peers));

    /* Build a list of the found peers and calculate hashes and load factors */
    for (P = sourcehash_peers, p = Config.peers; p; p = p->next) {
        if (!p->options.sourcehash)
            continue;

        if (p->weight == 0)
            continue;

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

        /* add it to our list of peers */
        *P++ = cbdataReference(p);
    }

    /* Sort our list on weight */
    qsort(sourcehash_peers, n_sourcehash_peers, sizeof(*sourcehash_peers), peerSortWeight);

    /* Calculate the load factor multipliers X_k
     *
     * X_1 = pow ((K*p_1), (1/K))
     * X_k = ([K-k+1] * [P_k - P_{k-1}])/(X_1 * X_2 * ... * X_{k-1})
     * X_k += pow ((X_{k-1}, {K-k+1})
     * X_k = pow (X_k, {1/(K-k+1)})
     * simplified to have X_1 part of the loop
     */
    K = n_sourcehash_peers;

    P_last = 0.0;       /* Empty P_0 */

    Xn = 1.0;           /* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;       /* Empty X_0, nullifies the first pow statement */

    for (k = 1; k <= K; ++k) {
        double Kk1 = (double) (K - k + 1);
        p = sourcehash_peers[k - 1];
        p->sourcehash.load_multiplier = (Kk1 * (p->sourcehash.load_factor - P_last)) / Xn;
        p->sourcehash.load_multiplier += pow(X_last, Kk1);
        p->sourcehash.load_multiplier = pow(p->sourcehash.load_multiplier, 1.0 / Kk1);
        Xn *= p->sourcehash.load_multiplier;
        X_last = p->sourcehash.load_multiplier;
        P_last = p->sourcehash.load_factor;
    }
}

static void
peerSourceHashRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("sourcehash", "peer sourcehash information",
                        peerSourceHashCachemgr, 0, 1);
}

CachePeer *
peerSourceHashSelectParent(HttpRequest * request)
{
    int k;
    const char *c;
    CachePeer *p = NULL;
    CachePeer *tp;
    unsigned int user_hash = 0;
    unsigned int combined_hash;
    double score;
    double high_score = 0;
    const char *key = NULL;
    char ntoabuf[MAX_IPSTRLEN];

    if (n_sourcehash_peers == 0)
        return NULL;

    key = request->client_addr.toStr(ntoabuf, sizeof(ntoabuf));

    /* calculate hash key */
    debugs(39, 2, "peerSourceHashSelectParent: Calculating hash for " << key);

    for (c = key; *c != 0; ++c)
        user_hash += ROTATE_LEFT(user_hash, 19) + *c;

    /* select CachePeer */
    for (k = 0; k < n_sourcehash_peers; ++k) {
        tp = sourcehash_peers[k];
        combined_hash = (user_hash ^ tp->sourcehash.hash);
        combined_hash += combined_hash * 0x62531965;
        combined_hash = ROTATE_LEFT(combined_hash, 21);
        score = combined_hash * tp->sourcehash.load_multiplier;
        debugs(39, 3, "peerSourceHashSelectParent: " << tp->name << " combined_hash " << combined_hash  <<
               " score " << std::setprecision(0) << score);

        if ((score > high_score) && peerHTTPOkay(tp, request)) {
            p = tp;
            high_score = score;
        }
    }

    if (p)
        debugs(39, 2, "peerSourceHashSelectParent: selected " << p->name);

    return p;
}

static void
peerSourceHashCachemgr(StoreEntry * sentry)
{
    CachePeer *p;
    int sumfetches = 0;
    storeAppendPrintf(sentry, "%24s %10s %10s %10s %10s\n",
                      "Hostname",
                      "Hash",
                      "Multiplier",
                      "Factor",
                      "Actual");

    for (p = Config.peers; p; p = p->next)
        sumfetches += p->stats.fetches;

    for (p = Config.peers; p; p = p->next) {
        storeAppendPrintf(sentry, "%24s %10x %10f %10f %10f\n",
                          p->name, p->sourcehash.hash,
                          p->sourcehash.load_multiplier,
                          p->sourcehash.load_factor,
                          sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }
}

