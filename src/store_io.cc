/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MemObject.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disk.h"
#include "store/Disks.h"

StoreIoStats store_io_stats;

/*
 * submit a request to create a cache object for writing.
 * The StoreEntry structure is sent as a hint to the filesystem
 * to what will be stored in this object, to allow the filesystem
 * to select different polices depending on object size or type.
 */
StoreIOState::Pointer
storeCreate(StoreEntry * e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * close_callback, void *callback_data)
{
    assert (e);

    ++store_io_stats.create.calls;

    /*
     * Pick the swapdir
     * We assume that the header has been packed by now ..
     */
    const sdirno dirn = storeDirSelectSwapDir(e);

    if (dirn == -1) {
        debugs(20, 2, "storeCreate: no swapdirs for " << *e);
        ++store_io_stats.create.select_fail;
        return NULL;
    }

    debugs(20, 2, "storeCreate: Selected dir " << dirn << " for " << *e);
    SwapDir *SD = dynamic_cast<SwapDir *>(INDEXSD(dirn));

    /* Now that we have a fs to use, call its storeCreate function */
    StoreIOState::Pointer sio = SD->createStoreIO(*e, file_callback, close_callback, callback_data);

    if (sio == NULL)
        ++store_io_stats.create.create_fail;
    else
        ++store_io_stats.create.success;

    return sio;
}

/*
 * storeOpen() is purely for reading ..
 */
StoreIOState::Pointer
storeOpen(StoreEntry * e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * callback,
          void *callback_data)
{
    return e->disk().openStoreIO(*e, file_callback, callback, callback_data);
}

void
storeClose(StoreIOState::Pointer sio, int how)
{
    if (sio->flags.closing) {
        debugs(20,3,HERE << "storeClose: flags.closing already set, bailing");
        return;
    }

    sio->flags.closing = true;

    debugs(20,3,HERE << "storeClose: calling sio->close(" << how << ")");
    sio->close(how);
}

void
storeRead(StoreIOState::Pointer sio, char *buf, size_t size, off_t offset, StoreIOState::STRCB * callback, void *callback_data)
{
    sio->read_(buf, size, offset, callback, callback_data);
}

void
storeIOWrite(StoreIOState::Pointer sio, char const *buf, size_t size, off_t offset, FREE * free_func)
{
    sio->write(buf,size,offset,free_func);
}

