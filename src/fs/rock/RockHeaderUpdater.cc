/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    IoCbParams io(buf, result);
    // TODO: Avoid Rock::StoreIOStateCb for jobs to protect jobs for "free".
    CallJobHere1(47, 7,
                 CbcPointer<HeaderUpdater>(static_cast<HeaderUpdater*>(data)),
                 Rock::HeaderUpdater,
                 noteRead,
                 io);
}

void
Rock::HeaderUpdater::noteRead(const Rock::HeaderUpdater::IoCbParams result)
{
    debugs(47, 7, result.size);
    if (!result.size) { // EOF
        stopReading("eof");
    } else {
        Must(result.size > 0);
        bytesRead += result.size;
        readerBuffer.rawAppendFinish(result.buf, result.size);
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
              readerBuffer.rawAppendStart(store->slotSize),
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

    // here, prefix is swap header plus HTTP reply header (i.e., updated bytes)
    uint64_t stalePrefixSz = 0;
    uint64_t freshPrefixSz = 0;

    off_t offset = 0; // current writing offset (for debugging)

    const auto &mem = update.entry->mem();

    {
        debugs(20, 7, "fresh store meta for " << *update.entry);
        size_t freshSwapHeaderSize = 0; // set by getSerialisedMetaData() below

        // There is a circular dependency between the correct/fresh value of
        // entry->swap_file_sz and freshSwapHeaderSize. We break that loop by
        // serializing zero swap_file_sz, just like the regular first-time
        // swapout code may do. De-serializing code will re-calculate it in
        // storeRebuildParseEntry(). TODO: Stop serializing entry->swap_file_sz.
        const auto savedEntrySwapFileSize = update.entry->swap_file_sz;
        update.entry->swap_file_sz = 0;
        const auto freshSwapHeader = update.entry->getSerialisedMetaData(freshSwapHeaderSize);
        update.entry->swap_file_sz = savedEntrySwapFileSize;

        Must(freshSwapHeader);
        writer->write(freshSwapHeader, freshSwapHeaderSize, 0, nullptr);
        stalePrefixSz += mem.swap_hdr_sz;
        freshPrefixSz += freshSwapHeaderSize;
        offset += freshSwapHeaderSize;
        xfree(freshSwapHeader);
    }

    {
        debugs(20, 7, "fresh HTTP header @ " << offset);
        const auto httpHeader = mem.freshestReply().pack();
        writer->write(httpHeader->content(), httpHeader->contentSize(), -1, nullptr);
        const auto &staleReply = mem.baseReply();
        Must(staleReply.hdr_sz >= 0); // for int-to-uint64_t conversion below
        Must(staleReply.hdr_sz > 0); // already initialized
        stalePrefixSz += staleReply.hdr_sz;
        freshPrefixSz += httpHeader->contentSize();
        offset += httpHeader->contentSize();
        delete httpHeader;
    }

    {
        debugs(20, 7, "moved HTTP body prefix @ " << offset);
        writer->write(exchangeBuffer.rawContent(), exchangeBuffer.length(), -1, nullptr);
        offset += exchangeBuffer.length();
        exchangeBuffer.clear();
    }

    debugs(20, 7, "wrote " << offset <<
           "; swap_file_sz delta: -" << stalePrefixSz << " +" << freshPrefixSz);

    // Optimistic early update OK: Our write lock blocks access to swap_file_sz.
    auto &swap_file_sz = update.fresh.anchor->basics.swap_file_sz;
    Must(swap_file_sz >= stalePrefixSz);
    swap_file_sz -= stalePrefixSz;
    swap_file_sz += freshPrefixSz;

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
        aBuilder.checkBuffer(); // cannot update an entry with invalid metadata
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

