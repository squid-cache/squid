#include "squid.h"


/*
 * submit a request to create a cache object for writing.
 * The StoreEntry structure is sent as a hint to the filesystem
 * to what will be stored in this object, to allow the filesystem
 * to select different polices depending on object size or type.
 */
storeIOState *
storeCreate(StoreEntry *e, STIOCB *file_callback, STIOCB *close_callback, void *callback_data)
{
    size_t objsize;
    sdirno dirn;
    SwapDir *SD;

    /* This is just done for logging purposes */
    objsize = objectLen(e);
    if (objsize != -1)
        objsize += e->mem_obj->swap_hdr_sz;

    /*
     * Pick the swapdir
     * We assume that the header has been packed by now ..
     */
    dirn = storeDirSelectSwapDir(e);
    if (dirn == -1) {
        debug(20, 2) ("storeCreate: no valid swapdirs for this object\n");
        return NULL;
    }
    debug (20, 2) ("storeCreate: Selected dir '%d' for obj size '%d'\n", dirn, objsize);
    SD = &Config.cacheSwap.swapDirs[dirn];

    /* Now that we have a fs to use, call its storeCreate function */
    return(SD->obj.create(SD, e, file_callback, close_callback, callback_data));

    /* Done */
}


/*
 * storeOpen() is purely for reading ..
 */
storeIOState *
storeOpen(StoreEntry *e, STFNCB * file_callback, STIOCB * callback,
  void *callback_data)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[e->swap_dirn];
    return SD->obj.open(SD, e, file_callback, callback, callback_data);
}

void
storeClose(storeIOState * sio)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_dirn];
    if (sio->flags.closing)
	return;
    sio->flags.closing = 1;
    SD->obj.close(SD, sio);
}

void
storeRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_dirn];
    SD->obj.read(SD, sio, buf, size, offset, callback, callback_data);
}

void
storeWrite(storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_dirn];
    SD->obj.write(SD, sio, buf, size, offset, free_func);
}

void
storeUnlink(StoreEntry *e)
{
    SwapDir *SD = INDEXSD(e->swap_dirn);
    SD->obj.unlink(SD, e);
}

off_t
storeOffset(storeIOState * sio)
{
    return sio->offset;
}
