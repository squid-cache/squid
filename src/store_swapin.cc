/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

void
storeSwapInStart(store_client * sc)
{
    StoreEntry *e = sc->entry;

    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
        /* We're still reloading and haven't validated this entry yet */
        return;
    }

    if (e->mem_status != NOT_IN_MEMORY)
        debugs(20, 3, "already IN_MEMORY");

    debugs(20, 3, *e << " " <<  e->getMD5Text());

    if (!e->hasDisk()) {
        debugs(20, DBG_IMPORTANT, "ERROR: Squid BUG: Attempt to swap in a not-stored entry " << *e << ". Salvaged.");
        return;
    }

    if (e->swapoutFailed()) {
        debugs(20, DBG_IMPORTANT, "ERROR: Squid BUG: Attempt to swap in a failed-to-store entry " << *e << ". Salvaged.");
        return;
    }

    assert(e->mem_obj != nullptr);
    sc->swapin_sio = storeOpen(e, storeSwapInFileClosed, sc);
}

static void
storeSwapInFileClosed(void *data, int errflag, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    debugs(20, 3, "storeSwapInFileClosed: sio=" << sc->swapin_sio.getRaw() << ", errflag=" << errflag);
    sc->swapin_sio = nullptr;

    if (sc->_callback.pending()) {
        assert (errflag <= 0);
        sc->noteSwapInDone(errflag);
    }

    ++statCounter.swap.ins;
}

