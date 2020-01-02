/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREIOSTATE_H
#define SQUID_STOREIOSTATE_H

#include "base/RefCount.h"
#include "cbdata.h"
#include "mem/forward.h"
#include "store/forward.h"

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

    StoreIOState(StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data);
    virtual ~StoreIOState();

    off_t offset() const {return offset_;}

    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data) = 0;
    /** write the given buffer and free it when it is no longer needed
     *  \param offset zero for the very first write and -1 for all other writes
     *  \retval false if write failed (callback has been or will be called)
     */
    virtual bool write(char const *buf, size_t size, off_t offset, FREE * free_func) = 0;

    typedef enum {
        wroteAll, ///< success: caller supplied all data it wanted to swap out
        writerGone, ///< failure: caller left before swapping out everything
        readerDone ///< success or failure: either way, stop swapping in
    } CloseHow;
    virtual void close(int how) = 0; ///< finish or abort swapping per CloseHow

    // Tests whether we are working with the primary/public StoreEntry chain.
    // Reads start reading the primary chain, but it may become secondary.
    // There are two store write kinds:
    // * regular writes that change (usually append) the entry visible to all and
    // * header updates that create a fresh chain (while keeping the stale one usable).
    bool touchingStoreEntry() const;

    sdirno swap_dirn;
    sfileno swap_filen;
    StoreEntry *e;      /* Need this so the FS layers can play god */
    mode_t mode;
    off_t offset_; ///< number of bytes written or read for this entry so far
    STFNCB *file_callback;  // XXX: Unused. TODO: Remove.
    STIOCB *callback;
    void *callback_data;

    struct {
        STRCB *callback;
        void *callback_data;
    } read;

    struct {
        bool closing;   /* debugging aid */
    } flags;
};

StoreIOState::Pointer storeCreate(StoreEntry *, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
StoreIOState::Pointer storeOpen(StoreEntry *, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
void storeClose(StoreIOState::Pointer, int how);
void storeRead(StoreIOState::Pointer, char *, size_t, off_t, StoreIOState::STRCB *, void *);
void storeIOWrite(StoreIOState::Pointer, char const *, size_t, off_t, FREE *);

#endif /* SQUID_STOREIOSTATE_H */

