/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Cache Array Routing Protocol */

#include "squid.h"
#include "CachePeer.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "Store.h"

#include <cmath>

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static int n_carp_peers = 0;
static CachePeer **carp_peers = NULL;
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
    int K;
    int k;
    double P_last, X_last, Xn;
    CachePeer *p;
    CachePeer **P;
    char *t;
    /* Clean up */

    for (k = 0; k < n_carp_peers; ++k) {
        cbdataReferenceDone(carp_peers[k]);
    }

    safe_free(carp_peers);
    n_carp_peers = 0;

    /* initialize cache manager before we have a chance to leave the execution path */
    carpRegisterWithCacheManager();

    /* find out which peers we have */

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.carp)
            continue;

        assert(p->type == PEER_PARENT);

        if (p->weight == 0)
            continue;

        ++n_carp_peers;

        W += p->weight;
    }

    if (n_carp_peers == 0)
        return;

    carp_peers = (CachePeer **)xcalloc(n_carp_peers, sizeof(*carp_peers));

    /* Build a list of the found peers and calculate hashes and load factors */
    for (P = carp_peers, p = Config.peers; p; p = p->next) {
        if (!p->options.carp)
            continue;

        if (p->weight == 0)
            continue;

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

        /* add it to our list of peers */
        *P = cbdataReference(p);
        ++P;
    }

    /* Sort our list on weight */
    qsort(carp_peers, n_carp_peers, sizeof(*carp_peers), peerSortWeight);

    /* Calculate the load factor multipliers X_k
     *
     * X_1 = pow ((K*p_1), (1/K))
     * X_k = ([K-k+1] * [P_k - P_{k-1}])/(X_1 * X_2 * ... * X_{k-1})
     * X_k += pow ((X_{k-1}, {K-k+1})
     * X_k = pow (X_k, {1/(K-k+1)})
     * simplified to have X_1 part of the loop
     */
    K = n_carp_peers;

    P_last = 0.0;       /* Empty P_0 */

    Xn = 1.0;           /* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;       /* Empty X_0, nullifies the first pow statement */

    for (k = 1; k <= K; ++k) {
        double Kk1 = (double) (K - k + 1);
        p = carp_peers[k - 1];
        p->carp.load_multiplier = (Kk1 * (p->carp.load_factor - P_last)) / Xn;
        p->carp.load_multiplier += pow(X_last, Kk1);
        p->carp.load_multiplier = pow(p->carp.load_multiplier, 1.0 / Kk1);
        Xn *= p->carp.load_multiplier;
        X_last = p->carp.load_multiplier;
        P_last = p->carp.load_factor;
    }
}

CachePeer *
carpSelectParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    int k;
    CachePeer *p = NULL;
    CachePeer *tp;
    unsigned int user_hash = 0;
    unsigned int combined_hash;
    double score;
    double high_score = 0;

    if (n_carp_peers == 0)
        return NULL;

    /* calculate hash key */
    debugs(39, 2, "carpSelectParent: Calculating hash for " << request->effectiveRequestUri());

    /* select CachePeer */
    for (k = 0; k < n_carp_peers; ++k) {
        SBuf key;
        tp = carp_peers[k];
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
                key.appendf(":%u", request->url.port());
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
        debugs(39, 3, "carpSelectParent: key=" << key << " name=" << tp->name << " combined_hash=" << combined_hash  <<
               " score=" << std::setprecision(0) << score);

        if ((score > high_score) && peerHTTPOkay(tp, ps)) {
            p = tp;
            high_score = score;
        }
    }

    if (p)
        debugs(39, 2, "carpSelectParent: selected " << p->name);

    return p;
}

static void
carpCachemgr(StoreEntry * sentry)
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
                          p->name, p->carp.hash,
                          p->carp.load_multiplier,
                          p->carp.load_factor,
                          sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }
}

