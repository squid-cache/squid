
/*
 * $Id: carp.cc,v 1.15 2001/01/12 00:37:15 wessels Exp $
 *
 * DEBUG: section 39    Cache Array Routing Protocol
 * AUTHOR: Eric Stern
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

#if USE_CARP

static OBJH carpCachemgr;

void
carpInit(void)
{
    /* calculate load factors */
    int K = 0;
    double a = 0.0;
    double dJ;
    double Xn;
    double P_last;
    double X_last;
    int k;
    peer *p;
    for (p = Config.peers; p; p = p->next) {
	a += p->carp.load_factor;
	K++;
    }
    if (a == 0.0) {
	for (p = Config.peers; p; p = p->next)
	    p->carp.load_multiplier = 1.0;
	return;
    }
    /*
     * sum of carp-load-factor's for all cache_peer's in squid.conf
     * must equal 1.0.  If this doesn't work, see
     * http://www.eskimo.com/~scs/C-faq/q14.4.html
     */
    assert(1000 == (int) (1000.0 * a));
    k = 1;
    P_last = 0;
    p = Config.peers;
    p->carp.load_multiplier = pow(p->carp.load_factor * K, 1.0 / K);
    Xn = p->carp.load_multiplier;
    P_last = p->carp.load_factor;
    X_last = p->carp.load_multiplier;
    if (!p->next)
	return;
    for (p = p->next; p; p = p->next) {
	k++;
	dJ = (double) (K - k + 1);
	p->carp.load_multiplier = (dJ * (p->carp.load_factor - P_last)) / Xn;
	p->carp.load_multiplier += pow(X_last, dJ);
	p->carp.load_multiplier = pow(p->carp.load_multiplier, 1 / dJ);
	Xn *= p->carp.load_multiplier;
	X_last = p->carp.load_multiplier;
	P_last = p->carp.load_factor;
    }
    cachemgrRegister("carp", "CARP information", carpCachemgr, 0, 1);
}

peer *
carpSelectParent(request_t * request)
{
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (((sizeof(unsigned long)*8)-(n)))))
    const char *c;
    peer *p = NULL;
    peer *tp;
    unsigned long url_hash = 0;
    unsigned long combined_hash;
    unsigned long high_score = 0;
    const char *url = urlCanonical(request);
    /* calculate url hash */
    debug(39, 2) ("carpSelectParent: CARP Calculating hash for %s\n", url);
    for (c = url; *c != 0; c++)
	url_hash += ROTATE_LEFT(url_hash, 19) + *c;
    /* select peer */
    for (tp = Config.peers; tp; tp = tp->next) {
	if (0.0 == tp->carp.load_factor)
	    continue;
	if (tp->tcp_up != PEER_TCP_MAGIC_COUNT)
	    continue;
	assert(tp->type == PEER_PARENT);
	combined_hash = (url_hash ^ tp->carp.hash);
	combined_hash += combined_hash * 0x62531965;
	combined_hash = ROTATE_LEFT(combined_hash, 21);
	combined_hash = combined_hash * tp->carp.load_multiplier;
	debug(39, 3) ("carpSelectParent: %s combined_hash %d\n",
	    tp->host, combined_hash);
	if ((combined_hash > high_score) && neighborUp(tp)) {
	    p = tp;
	    high_score = combined_hash;
	}
    }
    if (p)
	debug(39, 3) ("carpSelectParent: selected CARP %s\n", p->host);
    return p;
}

static void
carpCachemgr(StoreEntry * sentry)
{
    peer *p;
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
	    p->host, p->carp.hash,
	    p->carp.load_multiplier,
	    p->carp.load_factor,
	    sumfetches ? (double) p->stats.fetches / sumfetches : -1.0);
    }

}

#endif
