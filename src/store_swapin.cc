
/*
 * $Id: store_swapin.cc,v 1.40 2007/04/28 22:26:38 hno Exp $
 *
 * DEBUG: section 20    Storage Manager Swapin Functions
 * AUTHOR: Duane Wessels
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
#include "StoreClient.h"
#include "Store.h"

static StoreIOState::STIOCB storeSwapInFileClosed;
static StoreIOState::STFNCB storeSwapInFileNotify;

void
storeSwapInStart(store_client * sc)
{
    StoreEntry *e = sc->entry;
    assert(e->mem_status == NOT_IN_MEMORY);

    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
        /* We're still reloading and haven't validated this entry yet */
        return;
    }

    debugs(20, 3, "storeSwapInStart: called for : " << e->swap_dirn << " " <<  
           std::hex << std::setw(8) << std::setfill('0') << std::uppercase << 
           e->swap_filen << " " <<  e->getMD5Text());

    if (e->swap_status != SWAPOUT_WRITING && e->swap_status != SWAPOUT_DONE) {
        debugs(20, 1, "storeSwapInStart: bad swap_status (" << swapStatusStr[e->swap_status] << ")");
        return;
    }

    if (e->swap_filen < 0) {
        debugs(20, 1, "storeSwapInStart: swap_filen < 0");
        return;
    }

    assert(e->mem_obj != NULL);
    debugs(20, 3, "storeSwapInStart: Opening fileno " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << e->swap_filen);
    sc->swapin_sio = storeOpen(e, storeSwapInFileNotify, storeSwapInFileClosed, sc);
}

static void
storeSwapInFileClosed(void *data, int errflag, StoreIOState::Pointer self)
{
    store_client *sc = (store_client *)data;
    debugs(20, 3, "storeSwapInFileClosed: sio=" << sc->swapin_sio.getRaw() << ", errflag=" << errflag);
    sc->swapin_sio = NULL;

    if (sc->_callback.pending()) {
        assert (errflag <= 0);
        sc->callback(0, errflag ? true : false);
    }

    statCounter.swap.ins++;
}

static void
storeSwapInFileNotify(void *data, int errflag, StoreIOState::Pointer self)
{
    store_client *sc = (store_client *)data;
    StoreEntry *e = sc->entry;

    debugs(1, 3, "storeSwapInFileNotify: changing " << e->swap_filen << "/" <<
           e->swap_dirn << " to " << sc->swapin_sio->swap_filen << "/" <<
           sc->swapin_sio->swap_dirn);

    e->swap_filen = sc->swapin_sio->swap_filen;
    e->swap_dirn = sc->swapin_sio->swap_dirn;
}
