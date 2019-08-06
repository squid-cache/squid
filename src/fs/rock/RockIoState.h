/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_IO_STATE_H
#define SQUID_FS_ROCK_IO_STATE_H

#include "fs/rock/forward.h"
#include "fs/rock/RockSwapDir.h"
#include "sbuf/MemBlob.h"

class DiskFile;

namespace Rock
{

class DbCellHeader;
class SwapDir;

/// \ingroup Rock
class IoState: public ::StoreIOState
{
    MEMPROXY_CLASS(IoState);

public:
    typedef RefCount<IoState> Pointer;

    IoState(Rock::SwapDir::Pointer &aDir, StoreEntry *e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data);
    virtual ~IoState();

    void file(const RefCount<DiskFile> &aFile);

    // ::StoreIOState API
    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    virtual bool write(char const *buf, size_t size, off_t offset, FREE * free_func);
    virtual void close(int how);

    /// whether we are still waiting for the I/O results (i.e., not closed)
    bool stillWaiting() const { return theFile != NULL; }

    /// forwards read data (or an error) to the reader that initiated this I/O
    void handleReadCompletion(Rock::ReadRequest &request, const int rlen, const int errFlag);

    /// called by SwapDir::writeCompleted() after the last write and on error
    void finishedWriting(const int errFlag);

    /// notes that the disker has satisfied the given I/O request
    /// \returns whether all earlier I/O requests have been satisfied already
    bool expectedReply(const IoXactionId receivedId);

    /* one and only one of these will be set and locked; access via *Anchor() */
    const Ipc::StoreMapAnchor *readableAnchor_; ///< starting point for reading
    Ipc::StoreMapAnchor *writeableAnchor_; ///< starting point for writing

    /// the last db slot successfully read or written
    SlotId splicingPoint;
    /// when reading, this is the next slot we are going to read (if asked)
    /// when writing, this is the next slot to use after the last fresh slot
    SlotId staleSplicingPointNext;

private:
    const Ipc::StoreMapAnchor &readAnchor() const;
    Ipc::StoreMapAnchor &writeAnchor();
    const Ipc::StoreMapSlice &currentReadableSlice() const;

    void tryWrite(char const *buf, size_t size, off_t offset);
    size_t writeToBuffer(char const *buf, size_t size);
    void writeToDisk();

    void callReaderBack(const char *buf, int rlen);
    void callBack(int errflag);

    Rock::SwapDir::Pointer dir; ///< swap dir that initiated I/O
    const size_t slotSize; ///< db cell size
    int64_t objOffset; ///< object offset for current db slot

    /// The very first entry slot. Usually the same as anchor.first,
    /// but writers set anchor.first only after the first write is done.
    SlotId sidFirst;

    /// Unused by readers.
    /// For writers, the slot pointing (via .next) to sidCurrent.
    SlotId sidPrevious;

    /// For readers, the db slot currently being read from disk.
    /// For writers, the reserved db slot currently being filled (to be written).
    SlotId sidCurrent;

    /// Unused by readers.
    /// For writers, the reserved db slot that sidCurrent.next will point to.
    SlotId sidNext;

    /// the number of read or write requests we sent to theFile
    uint64_t requestsSent;

    /// the number of successful responses we received from theFile
    uint64_t repliesReceived;

    RefCount<DiskFile> theFile; // "file" responsible for this I/O
    MemBlob theBuf; // use for write content accumulation only
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_IO_STATE_H */

