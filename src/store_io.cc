#include "squid.h"
#include "Store.h"
#include "MemObject.h"
#include "SwapDir.h"

static struct
{

    struct
    {
        int calls;
        int select_fail;
        int create_fail;
        int success;
    }

    create;
}

store_io_stats;

OBJH storeIOStats;

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
    ssize_t objsize;
    sdirno dirn;
    RefCount<SwapDir> SD;

    store_io_stats.create.calls++;
    /* This is just done for logging purposes */
    objsize = e->objectLen();

    if (objsize != -1)
        objsize += e->mem_obj->swap_hdr_sz;

    /*
     * Pick the swapdir
     * We assume that the header has been packed by now ..
     */
    dirn = storeDirSelectSwapDir(e);

    if (dirn == -1) {
        debugs(20, 2, "storeCreate: no valid swapdirs for this object");
        store_io_stats.create.select_fail++;
        return NULL;
    }

    debugs(20, 2, "storeCreate: Selected dir '" << dirn << "' for obj size '" << objsize << "'");
    SD = dynamic_cast<SwapDir *>(INDEXSD(dirn));

    /* Now that we have a fs to use, call its storeCreate function */
    StoreIOState::Pointer sio = SD->createStoreIO(*e, file_callback, close_callback, callback_data);

    if (sio == NULL)
        store_io_stats.create.create_fail++;
    else
        store_io_stats.create.success++;

    return sio;
}

/*
 * storeOpen() is purely for reading ..
 */
StoreIOState::Pointer
storeOpen(StoreEntry * e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * callback,
          void *callback_data)
{
    return dynamic_cast<SwapDir *>(e->store().getRaw())->openStoreIO(*e, file_callback, callback, callback_data);
}

void
storeClose(StoreIOState::Pointer sio)
{
    if (sio->flags.closing) {
	debugs(20,3,HERE << "storeClose: flags.closing already set, bailing");
        return;
    }

    sio->flags.closing = 1;

    debugs(20,3,HERE << "storeClose: calling sio->close()");
    sio->close();
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

/*
 * Make this non-static so we can register
 * it from storeInit();
 */
void
storeIOStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Store IO Interface Stats\n");
    storeAppendPrintf(sentry, "create.calls %d\n", store_io_stats.create.calls);
    storeAppendPrintf(sentry, "create.select_fail %d\n", store_io_stats.create.select_fail);
    storeAppendPrintf(sentry, "create.create_fail %d\n", store_io_stats.create.create_fail);
    storeAppendPrintf(sentry, "create.success %d\n", store_io_stats.create.success);
}
