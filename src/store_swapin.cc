
/*
 * $Id: store_swapin.cc,v 1.17 1999/01/21 21:10:38 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager Swapin Functions
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

typedef struct swapin_ctrl_t {
    StoreEntry *e;
    char *path;
    SIH *callback;
    void *callback_data;
    store_client *sc;
} swapin_ctrl_t;

/* start swapping in */
/* callback_data will become the tag on which the stat/open can be aborted */
void
storeSwapInStart(StoreEntry * e, SIH * callback, void *callback_data)
{
    swapin_ctrl_t *ctrlp;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
	/* We're still reloading and haven't validated this entry yet */
	callback(-1, callback_data);
	return;
    }
    debug(20, 3) ("storeSwapInStart: called for %08X %s \n",
	e->swap_file_number, storeKeyText(e->key));
    assert(e->swap_status == SWAPOUT_WRITING || e->swap_status == SWAPOUT_DONE);
    assert(e->swap_file_number >= 0);
    assert(e->mem_obj != NULL);
    ctrlp = xmalloc(sizeof(swapin_ctrl_t));
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
    if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
	storeSwapInValidateComplete(ctrlp, 0, 0);
    else
	storeValidate(e, storeSwapInValidateComplete, ctrlp, callback_data);
}

void
storeSwapInValidateComplete(void *data, int retcode, int errcode)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e;
    if (retcode == -2 && errcode == -2) {
	xfree(ctrlp);
	return;
    }
    e = ctrlp->e;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (-1, ctrlp->callback_data);
	xfree(ctrlp);
	return;
    }
    ctrlp->path = xstrdup(storeSwapFullPath(e->swap_file_number, NULL));
    debug(20, 3) ("storeSwapInValidateComplete: Opening %s\n", ctrlp->path);
    store_open_disk_fd++;
    file_open(ctrlp->path,
	O_RDONLY,
	storeSwapInFileOpened,
	ctrlp,
	ctrlp->callback_data);
}

void
storeSwapInFileOpened(void *data, int fd, int errcode)
{
    swapin_ctrl_t *ctrlp = data;
    StoreEntry *e = ctrlp->e;
    MemObject *mem = e->mem_obj;
    struct stat sb;
    if (fd == -2 && errcode == -2) {
	xfree(ctrlp->path);
	xfree(ctrlp);
	store_open_disk_fd--;
	return;
    }
    assert(mem != NULL);
    assert(e->mem_status == NOT_IN_MEMORY);
    assert(e->swap_status == SWAPOUT_WRITING || e->swap_status == SWAPOUT_DONE);
    if (fd < 0) {
	debug(20, 3) ("storeSwapInFileOpened: Failed\n"
	    "\tFile:\t'%s'\n\t URL:\t'%s'\n",
	    ctrlp->path, storeUrl(e));
	storeEntryDump(e, 3);
	store_open_disk_fd--;
    } else if (e->swap_status != SWAPOUT_DONE) {
	(void) 0;
    } else if (fstat(fd, &sb) < 0) {
	debug(20, 1) ("storeSwapInFileOpened: fstat() FD %d: %s\n", fd, xstrerror());
	file_close(fd);
	store_open_disk_fd--;
	fd = -1;
    } else if (sb.st_size == 0 || sb.st_size != e->swap_file_sz) {
	debug(20, 1) ("storeSwapInFileOpened: %s: Size mismatch: %d(fstat) != %d(object)\n", ctrlp->path, (int) sb.st_size, e->swap_file_sz);
	file_close(fd);
	store_open_disk_fd--;
	fd = -1;
    }
    if (fd < 0) {
	storeReleaseRequest(e);
    } else {
	debug(20, 5) ("storeSwapInFileOpened: initialized '%s' for '%s'\n",
	    ctrlp->path, storeUrl(e));
    }
    (ctrlp->callback) (fd, ctrlp->callback_data);
    xfree(ctrlp->path);
    xfree(ctrlp);
}
