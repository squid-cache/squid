#include "squid.h"



storeIOState *
storeOpen(sfileno f, mode_t mode, STIOCB * callback, void *callback_data)
{
    assert(mode == O_RDONLY || mode == O_WRONLY);
    return storeUfsOpen(f, mode, callback, callback_data);
}

void
storeClose(storeIOState * sio)
{
    assert(!sio->flags.closing);
    sio->flags.closing = 1;
    storeUfsClose(sio);
}

void
storeRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    storeUfsRead(sio, buf, size, offset, callback, callback_data);
}

void
storeWrite(storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    storeUfsWrite(sio, buf, size, offset, free_func);
}

void
storeUnlink(sfileno f)
{
    storeUfsUnlink(f);
}

off_t
storeOffset(storeIOState * sio)
{
    return sio->offset;
}
