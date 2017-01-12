/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapin Functions */

#include "squid.h"
#include "globals.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_swapin.h"
#include "StoreClient.h"

static StoreIOState::STIOCB storeSwapInFileClosed;
static StoreIOState::STFNCB storeSwapInFileNotify;

void
storeSwapInStart(store_client * sc)
{
    StoreEntry *e = sc->entry;

    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
        /* We're still reloading and haven't validated this entry yet */
        return;
    }

    if (e->mem_status != NOT_IN_MEMORY)
        debugs(20, 3, HERE << "already IN_MEMORY");

    debugs(20, 3, "storeSwapInStart: called for : " << e->swap_dirn << " " <<
           std::hex << std::setw(8) << std::setfill('0') << std::uppercase <<
           e->swap_filen << " " <<  e->getMD5Text());

    if (e->swap_status != SWAPOUT_WRITING && e->swap_status != SWAPOUT_DONE) {
        debugs(20, DBG_IMPORTANT, "storeSwapInStart: bad swap_status (" << swapStatusStr[e->swap_status] << ")");
        return;
    }

    if (e->swap_filen < 0) {
        debugs(20, DBG_IMPORTANT, "storeSwapInStart: swap_filen < 0");
        return;
    }

    assert(e->mem_obj != NULL);
    debugs(20, 3, "storeSwapInStart: Opening fileno " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << e->swap_filen);
    sc->swapin_sio = storeOpen(e, storeSwapInFileNotify, storeSwapInFileClosed, sc);
}

static void
storeSwapInFileClosed(void *data, int errflag, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    debugs(20, 3, "storeSwapInFileClosed: sio=" << sc->swapin_sio.getRaw() << ", errflag=" << errflag);
    sc->swapin_sio = NULL;

    if (sc->_callback.pending()) {
        assert (errflag <= 0);
        sc->callback(0, errflag ? true : false);
    }

    ++statCounter.swap.ins;
}

static void
storeSwapInFileNotify(void *data, int, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    StoreEntry *e = sc->entry;

    debugs(1, 3, "storeSwapInFileNotify: changing " << e->swap_filen << "/" <<
           e->swap_dirn << " to " << sc->swapin_sio->swap_filen << "/" <<
           sc->swapin_sio->swap_dirn);

    assert(e->swap_filen < 0); // if this fails, call SwapDir::disconnect(e)
    e->swap_filen = sc->swapin_sio->swap_filen;
    e->swap_dirn = sc->swapin_sio->swap_dirn;
}

