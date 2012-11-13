
/*
 * DEBUG: section 39    Cache Array Routing Protocol
 * AUTHOR: Henrik Nordstrom
 * BASED ON: carp.c by Eric Stern and draft-vinod-carp-v1-03.txt
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
#include "CachePeer.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "SquidConfig.h"
#include "Store.h"
#include "URL.h"
#include "URLScheme.h"

#if HAVE_MATH_H
#include <math.h>
#endif

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

    P_last = 0.0;		/* Empty P_0 */

    Xn = 1.0;			/* Empty starting point of X_1 * X_2 * ... * X_{x-1} */

    X_last = 0.0;		/* Empty X_0, nullifies the first pow statement */

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
carpSelectParent(HttpRequest * request)
{
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
    debugs(39, 2, "carpSelectParent: Calculating hash for " << urlCanonical(request));

    /* select CachePeer */
    for (k = 0; k < n_carp_peers; ++k) {
        String key;
        tp = carp_peers[k];
        if (tp->options.carp_key.set) {
            //this code follows urlCanonical's pattern.
            //   corner cases should use the canonical URL
            if (tp->options.carp_key.scheme) {
                // temporary, until bug 1961 URL handling is fixed.
                const URLScheme sch = request->protocol;
                key.append(sch.const_str());
                if (key.size()) //if the scheme is not empty
                    key.append("://");
            }
            if (tp->options.carp_key.host) {
                key.append(request->GetHost());
            }
            if (tp->options.carp_key.port) {
                static char portbuf[7];
                snprintf(portbuf,7,":%d", request->port);
                key.append(portbuf);
            }
            if (tp->options.carp_key.path) {
                String::size_type pos;
                if ((pos=request->urlpath.find('?'))!=String::npos)
                    key.append(request->urlpath.substr(0,pos));
                else
                    key.append(request->urlpath);
            }
            if (tp->options.carp_key.params) {
                String::size_type pos;
                if ((pos=request->urlpath.find('?'))!=String::npos)
                    key.append(request->urlpath.substr(pos,request->urlpath.size()));
            }
        }
        // if the url-based key is empty, e.g. because the user is
        // asking to balance on the path but the request doesn't supply any,
        // then fall back to canonical URL

        if (key.size()==0)
            key=urlCanonical(request);

        for (const char *c = key.rawBuf(), *e=key.rawBuf()+key.size(); c < e; ++c)
            user_hash += ROTATE_LEFT(user_hash, 19) + *c;
        combined_hash = (user_hash ^ tp->carp.hash);
        combined_hash += combined_hash * 0x62531965;
        combined_hash = ROTATE_LEFT(combined_hash, 21);
        score = combined_hash * tp->carp.load_multiplier;
        debugs(39, 3, "carpSelectParent: key=" << key << " name=" << tp->name << " combined_hash=" << combined_hash  <<
               " score=" << std::setprecision(0) << score);

        if ((score > high_score) && peerHTTPOkay(tp, request)) {
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
