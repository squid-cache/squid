/*
 * $Id: carp.cc,v 1.6 1998/08/17 21:55:20 wessels Exp $
 *
 * DEBUG: section 39    Cache Array Routing Protocol
 * AUTHOR: Eric Stern
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

void
carpInit(void)
{
    /* calculate load factors */
    int K = 0;
    float a = 0.0;
    float Xn;
    float P_last;
    float X_last;
    int k;
    peer *p;
    for (p = Config.peers; p; p = p->next) {
	a += p->carp.load_factor;
	K++;
    }
    if (a == 0.0) {
	for (p = Config.peers; p; p = p->next)
	    p->carp.load_multiplier = 1;
	return;
    }
    /*
     * sum of carp-load-factor's for all cache_peer's in squid.conf
     * must equal 1.0
     */
    assert(a == 1.0);
    k = 1;
    P_last = 0;
    p = Config.peers;
    p->carp.load_multiplier = pow(K * p->carp.load_factor, 1 / K);
    Xn = p->carp.load_multiplier;
    P_last = p->carp.load_factor;
    X_last = p->carp.load_multiplier;
    if (!p->next)
	return;
    for (p = p->next; p; p = p->next) {
	p->carp.load_multiplier = ((K - k + 1) * (p->carp.load_factor - P_last)) / Xn;
	p->carp.load_multiplier += pow(X_last, K - k + 1);
	p->carp.load_multiplier = pow(p->carp.load_multiplier, 1 / (K - k + 1));
	Xn *= p->carp.load_multiplier;
	X_last = p->carp.load_multiplier;
	k++;
	P_last = p->carp.load_factor;
    }
}

peer *
carpSelectParent(request_t * request)
{
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
	url_hash += (url_hash << 19) + *c;
    /* select peer */
    for (tp = Config.peers; tp; tp = tp->next) {
	assert(tp->type == PEER_PARENT);
	combined_hash = (url_hash ^ tp->carp.hash);
	combined_hash += combined_hash * 0x62531965;
	combined_hash = combined_hash << 21;
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
#endif
