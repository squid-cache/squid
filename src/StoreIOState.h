
/*
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

#ifndef SQUID_STOREIOSTATE_H
#define SQUID_STOREIOSTATE_H

#include "base/RefCount.h"
#include "cbdata.h"

class StoreIOState : public RefCountable
{

public:
    typedef RefCount<StoreIOState> Pointer;

    /*
     * STRCB is the "store read callback".  STRCB functions are
     * passed to storeRead().  Examples of STRCB callbacks are:
     * storeClientReadBody
     * storeClientReadHeader
     */
    typedef void STRCB(void *their_data, const char *buf, ssize_t len, StoreIOState::Pointer self);

    /*
     * STFNCB is the "store file number callback."  It is called
     * when an underlying storage module has allocated the swap
     * file number and also indicates that the swap file has been
     * opened for reading or writing.  STFNCB functions are passed
     * to storeCreate() and storeOpen().  Examples of STFNCB callbacks
     * are:
     * storeSwapInFileNotify
     * storeSwapOutFileNotify
     */
    typedef void STFNCB(void *their_data, int errflag, StoreIOState::Pointer self);

    /*
     * STIOCB is the "store close callback" for store files.  It
     * is called when the store file is closed.  STIOCB functions
     * are passed to storeCreate() and storeOpen(). Examples of
     * STIOCB callbacks are:
     * storeSwapOutFileClosed
     * storeSwapInFileClosed
     */
    typedef void STIOCB(void *their_data, int errflag, StoreIOState::Pointer self);

    /* StoreIOState does not get mempooled - it's children do */
    void *operator new (size_t amount);
    void operator delete (void *address);
    virtual ~StoreIOState();

    StoreIOState();

    off_t offset() const;

    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data) = 0;
    virtual void write(char const *buf, size_t size, off_t offset, FREE * free_func) = 0;

    typedef enum {
        wroteAll, ///< success: caller supplied all data it wanted to swap out
        writerGone, ///< failure: caller left before swapping out everything
        readerDone ///< success or failure: either way, stop swapping in
    } CloseHow;
    virtual void close(int how) = 0; ///< finish or abort swapping per CloseHow

    sdirno swap_dirn;
    sfileno swap_filen;
    StoreEntry *e;		/* Need this so the FS layers can play god */
    mode_t mode;
    off_t offset_; ///< number of bytes written or read for this entry so far
    STFNCB *file_callback;	/* called on delayed sfileno assignments */
    STIOCB *callback;
    void *callback_data;

    struct {
        STRCB *callback;
        void *callback_data;
    } read;

    struct {
        bool closing;	/* debugging aid */
    } flags;
};

StoreIOState::Pointer storeCreate(StoreEntry *, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
StoreIOState::Pointer storeOpen(StoreEntry *, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
void storeClose(StoreIOState::Pointer, int how);
void storeRead(StoreIOState::Pointer, char *, size_t, off_t, StoreIOState::STRCB *, void *);
void storeIOWrite(StoreIOState::Pointer, char const *, size_t, off_t, FREE *);

#endif /* SQUID_STOREIOSTATE_H */
