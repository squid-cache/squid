#include "squid.h"



storeIOState *
storeOpen(sfileno f, mode_t mode, STIOCB * callback, void *callback_data)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[f >> SWAP_DIR_SHIFT];
    assert(mode == O_RDONLY || mode == O_WRONLY);
    return SD->open(f, mode, callback, callback_data);
}

void
storeClose(storeIOState * sio)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_file_number >> SWAP_DIR_SHIFT];
    assert(!sio->flags.closing);
    sio->flags.closing = 1;
    SD->close(sio);
}

void
storeRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_file_number >> SWAP_DIR_SHIFT];
    SD->read(sio, buf, size, offset, callback, callback_data);
}

void
storeWrite(storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[sio->swap_file_number >> SWAP_DIR_SHIFT];
    SD->write(sio, buf, size, offset, free_func);
}

void
storeUnlink(sfileno f)
{
    SwapDir *SD = &Config.cacheSwap.swapDirs[f >> SWAP_DIR_SHIFT];
    SD->unlink(f);
}

off_t
storeOffset(storeIOState * sio)
{
    return sio->offset;
}
