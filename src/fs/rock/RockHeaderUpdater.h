/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_HEADER_UPDATER_H
#define SQUID_FS_ROCK_HEADER_UPDATER_H

#include "base/AsyncJob.h"
#include "cbdata.h"
#include "fs/rock/forward.h"
#include "fs/rock/RockSwapDir.h"
#include "ipc/StoreMap.h"

namespace Rock
{

/// Updates HTTP headers of a single Rock store entry:
/// * reads old body data in the same slot as the last old headers slot, if any
/// * writes new headers (1+ slots)
/// * writes old data (0-2 slots)
/// * chains the new entry prefix (1+ slots) to the old entry suffix (0+ slots)
class HeaderUpdater: public AsyncJob
{
    CBDATA_CHILD(HeaderUpdater);

public:
    HeaderUpdater(const Rock::SwapDir::Pointer &aStore, const Ipc::StoreMapUpdate &update);
    virtual ~HeaderUpdater() override = default;

protected:
    /* AsyncJob API */
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

private:
    static StoreIOState::STRCB NoteRead;
    static StoreIOState::STIOCB NoteDoneReading;
    static StoreIOState::STIOCB NoteDoneWriting;

    void startReading();
    void stopReading(const char *why);
    void readMore(const char *why);
    void noteRead(ssize_t result);
    void noteDoneReading(int errflag);
    void parseReadBytes();

    void startWriting();
    void noteDoneWriting(int errflag);

    Rock::SwapDir::Pointer store; ///< cache_dir where the entry is stored
    Ipc::StoreMapUpdate update; ///< Ipc::StoreMap update reservation

    StoreIOState::Pointer reader; ///< reads old headers and old data
    StoreIOState::Pointer writer; ///< writes new headers and old data

    SBuf readerBuffer; ///< I/O buffer for a single read operation
    SBuf exchangeBuffer; ///< bytes read but not yet discarded or written
    uint64_t bytesRead; ///< total entry bytes read from Store so far

    int staleSwapHeaderSize; ///< stored size of the stale entry metadata

    SlotId staleSplicingPointNext; ///< non-updatable old HTTP body suffix start
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_HEADER_UPDATER_H */

