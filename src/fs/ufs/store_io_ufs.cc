
/*
 * $Id: store_io_ufs.cc,v 1.13 2002/10/13 20:35:27 robertc Exp $
 *
 * DEBUG: section 79    Storage Manager UFS Interface
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
#include "store_ufs.h"
#include "Store.h"
#include "ufscommon.h"


static DRCB storeUfsReadDone;
static DWCB storeUfsWriteDone;
static void storeUfsIOCallback(storeIOState * sio, int errflag);
static CBDUNL storeUfsIOFreeEntry;

CBDATA_TYPE(storeIOState);

/* === PUBLIC =========================================================== */

storeIOState *
storeUfsOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f = e->swap_filen;
    char *path = commonUfsDirFullPath(SD, f, NULL);
    storeIOState *sio;
    struct stat sb;
    int fd;
    debug(79, 3) ("storeUfsOpen: fileno %08X\n", f);
    fd = file_open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
	debug(79, 3) ("storeUfsOpen: got failure (%d)\n", errno);
	return NULL;
    }
    debug(79, 3) ("storeUfsOpen: opened FD %d\n", fd);
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeUfsIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = memPoolAlloc(ufs_state_pool);

    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_RDONLY | O_BINARY;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = e;
    ((ufsstate_t *) (sio->fsstate))->fd = fd;
    ((ufsstate_t *) (sio->fsstate))->flags.writing = 0;
    ((ufsstate_t *) (sio->fsstate))->flags.reading = 0;
    ((ufsstate_t *) (sio->fsstate))->flags.close_request = 0;
    if (fstat(fd, &sb) == 0)
	sio->st_size = sb.st_size;
    store_open_disk_fd++;

    /* We should update the heap/dlink position here ! */
    return sio;
}

storeIOState *
storeUfsCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    storeIOState *sio;
    int fd;
    int mode = (O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
    char *path;
    squidufsinfo_t *ufsinfo = (squidufsinfo_t *) SD->fsdata;
    sfileno filn;
    sdirno dirn;

    /* Allocate a number */
    dirn = SD->index;
    filn = commonUfsDirMapBitAllocate(SD);
    ufsinfo->suggest = filn + 1;
    /* Shouldn't we handle a 'bitmap full' error here? */
    path = commonUfsDirFullPath(SD, filn, NULL);

    debug(79, 3) ("storeUfsCreate: fileno %08X\n", filn);
    fd = file_open(path, mode);
    if (fd < 0) {
	debug(79, 3) ("storeUfsCreate: got failure (%d)\n", errno);
	return NULL;
    }
    debug(79, 3) ("storeUfsCreate: opened FD %d\n", fd);
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeUfsIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = memPoolAlloc(ufs_state_pool);

    sio->swap_filen = filn;
    sio->swap_dirn = dirn;
    sio->mode = mode;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = (StoreEntry *) e;
    ((ufsstate_t *) (sio->fsstate))->fd = fd;
    ((ufsstate_t *) (sio->fsstate))->flags.writing = 0;
    ((ufsstate_t *) (sio->fsstate))->flags.reading = 0;
    ((ufsstate_t *) (sio->fsstate))->flags.close_request = 0;
    store_open_disk_fd++;

    /* now insert into the replacement policy */
    commonUfsDirReplAdd(SD, e);
    return sio;
}

void
storeUfsClose(SwapDir * SD, storeIOState * sio)
{
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;

    debug(79, 3) ("storeUfsClose: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, ufsstate->fd);
    if (ufsstate->flags.reading || ufsstate->flags.writing) {
	ufsstate->flags.close_request = 1;
	return;
    }
    storeUfsIOCallback(sio, 0);
}

void
storeUfsRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;

    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = cbdataReference(callback_data);
    debug(79, 3) ("storeUfsRead: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, ufsstate->fd);
    sio->offset = offset;
    ufsstate->flags.reading = 1;
    file_read(ufsstate->fd,
	buf,
	size,
	offset,
	storeUfsReadDone,
	sio);
}

void
storeUfsWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;
    debug(79, 3) ("storeUfsWrite: dirn %d, fileno %08X, FD %d\n", sio->swap_dirn, sio->swap_filen, ufsstate->fd);
    ufsstate->flags.writing = 1;
    file_write(ufsstate->fd,
	offset,
	buf,
	size,
	storeUfsWriteDone,
	sio,
	free_func);
}

void
storeUfsUnlink(SwapDir * SD, StoreEntry * e)
{
    debug(79, 3) ("storeUfsUnlink: fileno %08X\n", e->swap_filen);
    commonUfsDirReplRemove(e);
    commonUfsDirMapBitReset(SD, e->swap_filen);
    commonUfsDirUnlinkFile(SD, e->swap_filen);
}

/*  === STATIC =========================================================== */

static void
storeUfsReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    storeIOState *sio = (storeIOState *)my_data;
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;
    STRCB *callback;
    void *cbdata;
    ssize_t rlen;

    debug(79, 3) ("storeUfsReadDone: dirno %d, fileno %08X, FD %d, len %d\n",
	sio->swap_dirn, sio->swap_filen, fd, len);
    ufsstate->flags.reading = 0;
    if (errflag) {
	debug(79, 3) ("storeUfsReadDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	rlen = (ssize_t) len;
	sio->offset += len;
    }
    assert(sio->read.callback);
    assert(sio->read.callback_data);
    callback = sio->read.callback;
    sio->read.callback = NULL;
    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
	callback(cbdata, buf, (size_t) rlen);
}

static void
storeUfsWriteDone(int fd, int errflag, size_t len, void *my_data)
{
    storeIOState *sio = (storeIOState *)my_data;
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;
    debug(79, 3) ("storeUfsWriteDone: dirno %d, fileno %08X, FD %d, len %ld\n",
	sio->swap_dirn, sio->swap_filen, fd, (long int) len);
    ufsstate->flags.writing = 0;
    if (errflag) {
	debug(79, 0) ("storeUfsWriteDone: got failure (%d)\n", errflag);
	storeUfsIOCallback(sio, errflag);
	return;
    }
    sio->offset += len;
    if (ufsstate->flags.close_request)
	storeUfsIOCallback(sio, errflag);
}

static void
storeUfsIOCallback(storeIOState * sio, int errflag)
{
    ufsstate_t *ufsstate = (ufsstate_t *) sio->fsstate;
    void *cbdata;
    debug(79, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    if (ufsstate->fd > -1) {
	file_close(ufsstate->fd);
	store_open_disk_fd--;
    }
    if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
	sio->callback(cbdata, errflag, sio);
    sio->callback = NULL;
    cbdataFree(sio);
}


/*
 * Clean up any references from the SIO before it get's released.
 */
static void
storeUfsIOFreeEntry(void *sio)
{
    memPoolFree(ufs_state_pool, ((storeIOState *) sio)->fsstate);
}
