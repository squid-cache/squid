/*
 * $Id: store_digest.cc,v 1.1 1998/04/02 17:11:27 rousskov Exp $
 *
 * DEBUG: section 71    Store Digest Manager
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

void
storeDigestInit()
{
    /*
     * To-Do: Bloom proved that the optimal filter utilization is 50% (half of
     * the bits are off). However, we do not have a formula to calculate the 
     * number of _entries_ we want to pre-allocate for.
     * Use 1.5*max#entries because 2*max#entries gives about 40% utilization.
     */
    const int cap = (int)(1.5 * Config.Swap.maxSize / Config.Store.avgObjectSize);
#if SQUID_MAINTAIN_CACHE_DIGEST
    store_digest = cacheDigestCreate(cap);
#else
    store_digest = NULL;
#endif
    cachemgrRegister("store_digest", "Store Digest",
        storeDigestReport, 0);
}

/* rebuilds digest from scratch */
void
storeDigestRebuild()
{
    assert(store_digest);
}

void
storeDigestReport(StoreEntry *e)
{
    if (store_digest) {
	cacheDigestReport(store_digest, "store", e);
    } else {
	storeAppendPrintf(e, "store digest: disabled.\n");
    }
}

