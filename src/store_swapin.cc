
/*
 * $Id: store_swapin.cc,v 1.22 2000/03/06 16:23:35 wessels Exp $
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
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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

static STIOCB storeSwapInFileClosed;

void
storeSwapInStart(store_client * sc)
{
    StoreEntry *e = sc->entry;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!EBIT_TEST(e->flags, ENTRY_VALIDATED)) {
	/* We're still reloading and haven't validated this entry yet */
	return;
    }
    debug(20, 3) ("storeSwapInStart: called for %08X %s \n",
	e->swap_file_number, storeKeyText(e->key));
    if (e->swap_status != SWAPOUT_WRITING && e->swap_status != SWAPOUT_DONE) {
	debug(20, 1) ("storeSwapInStart: bad swap_status (%s)\n",
	    swapStatusStr[e->swap_status]);
	return;
    }
    if (e->swap_file_number < 0) {
	debug(20, 1) ("storeSwapInStart: swap_file_number < 0\n");
	return;
    }
    assert(e->mem_obj != NULL);
    debug(20, 3) ("storeSwapInStart: Opening fileno %08X\n",
	e->swap_file_number);
    sc->swapin_sio = storeOpen(e->swap_file_number,
	O_RDONLY,
	storeSwapInFileClosed,
	sc);
    cbdataLock(sc->swapin_sio);
}

static void
storeSwapInFileClosed(void *data, int errflag, storeIOState * sio)
{
    store_client *sc = data;
    STCB *callback;
    debug(20, 3) ("storeSwapInFileClosed: sio=%p, errflag=%d\n",
	sio, errflag);
    cbdataUnlock(sio);
    sc->swapin_sio = NULL;
    if ((callback = sc->callback)) {
	assert(errflag <= 0);
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, errflag);
    }
}
