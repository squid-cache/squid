/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "Debug.h"
#include "fs/rock/RockHeaderUpdater.h"
#include "fs/rock/RockIoState.h"
#include "mime_header.h"
#include "Store.h"
#include "StoreMetaUnpacker.h"

CBDATA_NAMESPACED_CLASS_INIT(Rock, HeaderUpdater);

Rock::HeaderUpdater::HeaderUpdater(const Rock::SwapDir::Pointer &aStore, const Ipc::StoreMapUpdate &anUpdate):
    AsyncJob("Rock::HeaderUpdater"),
    store(aStore),
    update(anUpdate),
    reader(),
    writer(),
    bytesRead(0),
    staleSwapHeaderSize(0),
    staleSplicingPointNext(-1)
{
    // TODO: Consider limiting the number of concurrent store updates.
}

bool
Rock::HeaderUpdater::doneAll() const
{
    return !reader && !writer && AsyncJob::doneAll();
}

void
Rock::HeaderUpdater::swanSong()
{
    if (update.stale || update.fresh)
        store->map->abortUpdating(update);

    if (reader) {
        reader->close(StoreIOState::readerDone);
        reader = nullptr;
    }

    if (writer) {
        writer->close(StoreIOState::writerGone);
        // Emulate SwapDir::disconnect() that writeCompleted(err) hopes for.
        // Also required to avoid IoState destructor assertions.
        // We can do this because we closed update earlier or aborted it above.
        dynamic_cast<IoState&>(*writer).writeableAnchor_ = nullptr;
        writer = nullptr;
    }

    AsyncJob::swanSong();
}

void
Rock::HeaderUpdater::start()
{
    Must(update.entry);
    Must(update.stale);
    Must(update.fresh);
    startReading();
}

void
Rock::HeaderUpdater::startReading()
{
    reader = store->openStoreIO(
                 *update.entry,
                 nullptr, // unused; see StoreIOState::file_callback
                 &NoteDoneReading,
                 this);
    readMore("need swap entry metadata");
}

void
Rock::HeaderUpdater::stopReading(const char *why)
{
    debugs(47, 7, why);

    Must(reader);
    const IoState &rockReader = dynamic_cast<IoState&>(*reader);
    update.stale.splicingPoint = rockReader.splicingPoint;
    staleSplicingPointNext = rockReader.staleSplicingPointNext;
    debugs(47, 5, "stale chain ends at " << update.stale.splicingPoint <<
           " body continues at " << staleSplicingPointNext);

    reader->close(StoreIOState::readerDone); // calls noteDoneReading(0)
    reader = nullptr; // so that swanSong() does not try to close again
}

void
Rock::HeaderUpdater::NoteRead(void *data, const char *buf, ssize_t result, StoreIOState::Pointer)
{
    // TODO: Avoid Rock::StoreIOStateCb for jobs to protect jobs for "free".
    CallJobHere1(47, 7,
                 CbcPointer<HeaderUpdater>(static_cast<HeaderUpdater*>(data)),
                 Rock::HeaderUpdater,
                 noteRead,
                 result);
}

void
Rock::HeaderUpdater::noteRead(ssize_t result)
{
    debugs(47, 7, result);
    if (!result) { // EOF
        stopReading("eof");
    } else {
        Must(result > 0);
        bytesRead += result;
        readerBuffer.forceSize(readerBuffer.length() + result);
        exchangeBuffer.append(readerBuffer);
        debugs(47, 7, "accumulated " << exchangeBuffer.length());
    }

    parseReadBytes();
}

void
Rock::HeaderUpdater::readMore(const char *why)
{
    debugs(47, 7, "from " << bytesRead << " because " << why);
    Must(reader);
    readerBuffer.clear();
    storeRead(reader,
              readerBuffer.rawSpace(store->slotSize),
              store->slotSize,
              bytesRead,
              &NoteRead,
              this);
}

void
Rock::HeaderUpdater::NoteDoneReading(void *data, int errflag, StoreIOState::Pointer)
{
    // TODO: Avoid Rock::StoreIOStateCb for jobs to protect jobs for "free".
    CallJobHere1(47, 7,
                 CbcPointer<HeaderUpdater>(static_cast<HeaderUpdater*>(data)),
                 Rock::HeaderUpdater,
                 noteDoneReading,
                 errflag);
}

void
Rock::HeaderUpdater::noteDoneReading(int errflag)
{
    debugs(47, 5, errflag << " writer=" << writer);
    if (!reader) {
        Must(!errflag); // we only initiate successful closures
        Must(writer); // otherwise we would be done() and would not be called
    } else {
        reader = nullptr; // we are done reading
        Must(errflag); // any external closures ought to be errors
        mustStop("read error");
    }
}

void
Rock::HeaderUpdater::startWriting()
{
    writer = store->createUpdateIO(
                 update,
                 nullptr, // unused; see StoreIOState::file_callback
                 &NoteDoneWriting,
                 this);
    Must(writer);

    IoState &rockWriter = dynamic_cast<IoState&>(*writer);
    rockWriter.staleSplicingPointNext = staleSplicingPointNext;

    off_t offset = 0; // current writing offset (for debugging)

    {
        debugs(20, 7, "fresh store meta for " << *update.entry);
        const char *freshSwapHeader = update.entry->getSerialisedMetaData();
        const auto freshSwapHeaderSize = update.entry->mem_obj->swap_hdr_sz;
        Must(freshSwapHeader);
        writer->write(freshSwapHeader, freshSwapHeaderSize, 0, nullptr);
        offset += freshSwapHeaderSize;
        xfree(freshSwapHeader);
    }

    {
        debugs(20, 7, "fresh HTTP header @ " << offset);
        MemBuf *httpHeader = update.entry->mem_obj->getReply()->pack();
        writer->write(httpHeader->content(), httpHeader->contentSize(), -1, nullptr);
        offset += httpHeader->contentSize();
        delete httpHeader;
    }

    {
        debugs(20, 7, "moved HTTP body prefix @ " << offset);
        writer->write(exchangeBuffer.rawContent(), exchangeBuffer.length(), -1, nullptr);
        offset += exchangeBuffer.length();
        exchangeBuffer.clear();
    }

    debugs(20, 7, "wrote " << offset);

    writer->close(StoreIOState::wroteAll); // should call noteDoneWriting()
}

void
Rock::HeaderUpdater::NoteDoneWriting(void *data, int errflag, StoreIOState::Pointer)
{
    CallJobHere1(47, 7,
                 CbcPointer<HeaderUpdater>(static_cast<HeaderUpdater*>(data)),
                 Rock::HeaderUpdater,
                 noteDoneWriting,
                 errflag);
}

void
Rock::HeaderUpdater::noteDoneWriting(int errflag)
{
    debugs(47, 5, errflag << " reader=" << reader);
    Must(!errflag);
    Must(!reader); // if we wrote everything, then we must have read everything

    Must(writer);
    IoState &rockWriter = dynamic_cast<IoState&>(*writer);
    update.fresh.splicingPoint = rockWriter.splicingPoint;
    debugs(47, 5, "fresh chain ends at " << update.fresh.splicingPoint);
    store->map->closeForUpdating(update);
    rockWriter.writeableAnchor_ = nullptr;
    writer = nullptr; // we are done writing

    Must(doneAll());
}

void
Rock::HeaderUpdater::parseReadBytes()
{
    if (!staleSwapHeaderSize) {
        StoreMetaUnpacker aBuilder(
            exchangeBuffer.rawContent(),
            exchangeBuffer.length(),
            &staleSwapHeaderSize);
        // Squid assumes that metadata always fits into a single db slot
        Must(aBuilder.isBufferSane()); // cannot update what we cannot parse
        debugs(47, 7, "staleSwapHeaderSize=" << staleSwapHeaderSize);
        Must(staleSwapHeaderSize > 0);
        exchangeBuffer.consume(staleSwapHeaderSize);
    }

    const size_t staleHttpHeaderSize = headersEnd(
                                           exchangeBuffer.rawContent(),
                                           exchangeBuffer.length());
    debugs(47, 7, "staleHttpHeaderSize=" << staleHttpHeaderSize);
    if (!staleHttpHeaderSize) {
        readMore("need more stale HTTP reply header data");
        return;
    }

    exchangeBuffer.consume(staleHttpHeaderSize);
    debugs(47, 7, "httpBodySizePrefix=" << exchangeBuffer.length());

    stopReading("read the last HTTP header slot");
    startWriting();
}

