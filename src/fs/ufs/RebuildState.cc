/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "fs_io.h"
#include "globals.h"
#include "RebuildState.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "store/Disks.h"
#include "store_key_md5.h"
#include "store_rebuild.h"
#include "StoreSwapLogData.h"
#include "tools.h"
#include "UFSSwapLogParser.h"

#include <cerrno>
#include <cmath>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

CBDATA_NAMESPACED_CLASS_INIT(Fs::Ufs,RebuildState);

Fs::Ufs::RebuildState::RebuildState(RefCount<UFSSwapDir> aSwapDir) :
    sd(aSwapDir),
    n_read(0),
    LogParser(NULL),
    curlvl1(0),
    curlvl2(0),
    in_dir(0),
    done(0),
    fn(0),
    entry(NULL),
    td(NULL),
    fromLog(true),
    _done(false),
    cbdata(NULL)
{
    *fullpath = 0;
    *fullfilename = 0;

    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use commonUfsDirRebuildFromSwapLog(), otherwise we'll
     * use commonUfsDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    int clean = 0; //TODO: change to bool
    int zeroLengthLog = 0;
    FILE *fp = sd->openTmpSwapLog(&clean, &zeroLengthLog);

    if (fp && !zeroLengthLog)
        LogParser = Fs::Ufs::UFSSwapLogParser::GetUFSSwapLogParser(fp);

    if (LogParser == NULL ) {
        fromLog = false;

        if (fp != NULL)
            fclose(fp);

    } else {
        fromLog = true;
        flags.clean = (clean != 0);
    }

    if (!clean)
        flags.need_to_validate = true;

    debugs(47, DBG_IMPORTANT, "Rebuilding storage in " << sd->path << " (" <<
           (clean ? "clean log" : (LogParser ? "dirty log" : "no log")) << ")");
}

Fs::Ufs::RebuildState::~RebuildState()
{
    sd->closeTmpSwapLog();

    if (LogParser)
        delete LogParser;
}

void
Fs::Ufs::RebuildState::RebuildStep(void *data)
{
    RebuildState *rb = (RebuildState *)data;
    if (!reconfiguring)
        rb->rebuildStep();

    // delay storeRebuildComplete() when reconfiguring to protect storeCleanup()
    if (!rb->isDone() || reconfiguring)
        eventAdd("storeRebuild", RebuildStep, rb, 0.01, 1);
    else {
        -- StoreController::store_dirs_rebuilding;
        storeRebuildComplete(&rb->counts);
        delete rb;
    }
}

/// load entries from swap.state or files until we run out of entries or time
void
Fs::Ufs::RebuildState::rebuildStep()
{
    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, disk I/Os, etc.
    const int maxSpentMsec = 50; // keep small: most RAM I/Os are under 1ms
    const timeval loopStart = current_time;

    const int totalEntries = LogParser ? LogParser->SwapLogEntries() : -1;

    while (!isDone()) {
        if (fromLog)
            rebuildFromSwapLog();
        else
            rebuildFromDirectory();

        // TODO: teach storeRebuildProgress to handle totalEntries <= 0
        if (totalEntries > 0 && (n_read % 4000 == 0))
            storeRebuildProgress(sd->index, totalEntries, n_read);

        if (opt_foreground_rebuild)
            continue; // skip "few entries at a time" check below

        getCurrentTime();
        const double elapsedMsec = tvSubMsec(loopStart, current_time);
        if (elapsedMsec > maxSpentMsec || elapsedMsec < 0) {
            debugs(47, 5, HERE << "pausing after " << n_read << " entries in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/n_read) << "ms per entry");
            break;
        }
    }
}

/// process one cache file
void
Fs::Ufs::RebuildState::rebuildFromDirectory()
{
    cache_key key[SQUID_MD5_DIGEST_LENGTH];

    struct stat sb;
    int fd = -1;
    debugs(47, 3, HERE << "DIR #" << sd->index);

    assert(fd == -1);
    sfileno filn = 0;
    int size;
    fd = getNextFile(&filn, &size);

    if (fd == -2) {
        debugs(47, DBG_IMPORTANT, "Done scanning " << sd->path << " dir (" <<
               n_read << " entries)");
        _done = true;
        return;
    } else if (fd < 0) {
        return;
    }

    assert(fd > -1);
    /* lets get file stats here */

    ++n_read;

    if (fstat(fd, &sb) < 0) {
        int xerrno = errno;
        debugs(47, DBG_IMPORTANT, MYNAME << "fstat(FD " << fd << "): " << xstrerr(xerrno));
        file_close(fd);
        --store_open_disk_fd;
        fd = -1;
        return;
    }

    MemBuf buf;
    buf.init(SM_PAGE_SIZE, SM_PAGE_SIZE);
    if (!storeRebuildLoadEntry(fd, sd->index, buf, counts))
        return;

    const uint64_t expectedSize = sb.st_size > 0 ?
                                  static_cast<uint64_t>(sb.st_size) : 0;

    StoreEntry tmpe;
    const bool parsed = storeRebuildParseEntry(buf, tmpe, key, counts,
                        expectedSize);

    file_close(fd);
    --store_open_disk_fd;
    fd = -1;

    bool accepted = parsed && tmpe.swap_file_sz > 0;
    if (parsed && !accepted) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring ufs cache entry with " <<
               "unknown size: " << tmpe);
        accepted = false;
    }

    if (!accepted) {
        // XXX: shouldn't this be a call to commonUfsUnlink?
        sd->unlinkFile(filn); // should we unlink in all failure cases?
        return;
    }

    addIfFresh(key,
               filn,
               tmpe.swap_file_sz,
               tmpe.expires,
               tmpe.timestamp,
               tmpe.lastref,
               tmpe.lastModified(),
               tmpe.refcount,
               tmpe.flags);
}

/// if the loaded entry metadata is still relevant, indexes the entry
void
Fs::Ufs::RebuildState::addIfFresh(const cache_key *key,
                                  sfileno file_number,
                                  uint64_t swap_file_sz,
                                  time_t expires,
                                  time_t timestamp,
                                  time_t lastref,
                                  time_t lastmod,
                                  uint32_t refcount,
                                  uint16_t newFlags)
{
    if (!evictStaleAndContinue(key, lastref, counts.dupcount))
        return;

    ++counts.objcount;
    const auto addedEntry = sd->addDiskRestore(key,
                            file_number,
                            swap_file_sz,
                            expires,
                            timestamp,
                            lastref,
                            lastmod,
                            refcount,
                            newFlags,
                            0 /* XXX: unused */);
    storeDirSwapLog(addedEntry, SWAP_LOG_ADD);
}

/// Evicts a matching entry if it was last touched before caller's maxRef.
/// \returns false only if the matching entry was touched at or after maxRef,
/// indicating that the caller has supplied outdated maxRef.
bool
Fs::Ufs::RebuildState::evictStaleAndContinue(const cache_key *candidateKey, const time_t maxRef, int &staleCount)
{
    if (auto *indexedEntry = Store::Root().peek(candidateKey)) {

        if (indexedEntry->lastref >= maxRef) {
            indexedEntry->abandon("Fs::Ufs::RebuildState::evictStaleAndContinue");
            ++counts.clashcount;
            return false;
        }

        ++staleCount;
        indexedEntry->release(true); // evict previously indexedEntry
    }

    return true;
}

/// process one swap log entry
void
Fs::Ufs::RebuildState::rebuildFromSwapLog()
{
    StoreSwapLogData swapData;

    if (LogParser->ReadRecord(swapData) != 1) {
        debugs(47, DBG_IMPORTANT, "Done reading " << sd->path << " swaplog (" << n_read << " entries)");
        LogParser->Close();
        delete LogParser;
        LogParser = NULL;
        _done = true;
        return;
    }

    ++n_read;

    if (!swapData.sane()) {
        ++counts.invalid;
        return;
    }

    /*
     * BC: during 2.4 development, we changed the way swap file
     * numbers are assigned and stored.  The high 16 bits used
     * to encode the SD index number.  There used to be a call
     * to storeDirProperFileno here that re-assigned the index
     * bits.  Now, for backwards compatibility, we just need
     * to mask it off.
     */
    swapData.swap_filen &= 0x00FFFFFF;

    debugs(47, 3, HERE << swap_log_op_str[(int) swapData.op]  << " " <<
           storeKeyText(swapData.key)  << " "<< std::setfill('0') <<
           std::hex << std::uppercase << std::setw(8) <<
           swapData.swap_filen);

    if (swapData.op == SWAP_LOG_ADD) {
        (void) 0;
    } else if (swapData.op == SWAP_LOG_DEL) {
        // remove any older or same-age entry; +1 covers same-age entries
        (void)evictStaleAndContinue(swapData.key, swapData.lastref+1, counts.cancelcount);
        return;
    } else {
        const double
        x = ::log(static_cast<double>(++counts.bad_log_op)) / ::log(10.0);

        if (0.0 == x - (double) (int) x)
            debugs(47, DBG_IMPORTANT, "WARNING: " << counts.bad_log_op << " invalid swap log entries found");

        ++counts.invalid;

        return;
    }

    ++counts.scancount; // XXX: should not this be incremented earlier?

    if (!sd->validFileno(swapData.swap_filen, 0)) {
        ++counts.invalid;
        return;
    }

    if (EBIT_TEST(swapData.flags, KEY_PRIVATE)) {
        ++counts.badflags;
        return;
    }

    if (sd->mapBitTest(swapData.swap_filen)) {
        // While we were scanning the logs, some (unrelated) entry was added to
        // our disk using our logged swap_filen. We could change our swap_filen
        // and move the store file, but there is no Store API to do that (TODO).
        ++counts.clashcount;
        return;
    }

    addIfFresh(swapData.key,
               swapData.swap_filen,
               swapData.swap_file_sz,
               swapData.expires,
               swapData.timestamp,
               swapData.lastref,
               swapData.lastmod,
               swapData.refcount,
               swapData.flags);
}

int
Fs::Ufs::RebuildState::getNextFile(sfileno * filn_p, int *)
{
    int fd = -1;
    int dirs_opened = 0;
    debugs(47, 3, HERE << "flag=" << flags.init  << ", " <<
           sd->index  << ": /"<< std::setfill('0') << std::hex <<
           std::uppercase << std::setw(2) << curlvl1  << "/" << std::setw(2) <<
           curlvl2);

    if (done)
        return -2;

    while (fd < 0 && done == 0) {
        fd = -1;

        if (!flags.init) {  /* initialize, open first file */
            // XXX: 0's should not be needed, constructor inits now
            done = 0;
            curlvl1 = 0;
            curlvl2 = 0;
            in_dir = 0;
            flags.init = true;
            assert(Config.cacheSwap.n_configured > 0);
        }

        if (0 == in_dir) {  /* we need to read in a new directory */
            snprintf(fullpath, sizeof(fullpath), "%s/%02X/%02X",
                     sd->path,
                     curlvl1, curlvl2);

            if (dirs_opened)
                return -1;

            td = opendir(fullpath);

            ++dirs_opened;

            if (!td) {
                int xerrno = errno;
                debugs(47, DBG_IMPORTANT, MYNAME << "error in opendir (" << fullpath << "): " << xstrerr(xerrno));
            } else {
                entry = readdir(td);    /* skip . and .. */
                entry = readdir(td);

                if (entry == NULL && errno == ENOENT)
                    debugs(47, DBG_IMPORTANT, HERE << "WARNING: directory does not exist!");
                debugs(47, 3, HERE << "Directory " << fullpath);
            }
        }

        if (td != NULL && (entry = readdir(td)) != NULL) {
            ++in_dir;

            if (sscanf(entry->d_name, "%x", &fn) != 1) {
                debugs(47, 3, HERE << "invalid entry " << entry->d_name);
                continue;
            }

            if (!UFSSwapDir::FilenoBelongsHere(fn, sd->index, curlvl1, curlvl2)) {
                debugs(47, 3, HERE << std::setfill('0') <<
                       std::hex << std::uppercase << std::setw(8) << fn  <<
                       " does not belong in " << std::dec << sd->index  << "/" <<
                       curlvl1  << "/" << curlvl2);

                continue;
            }

            if (sd->mapBitTest(fn)) {
                debugs(47, 3, HERE << "Locked, continuing with next.");
                continue;
            }

            snprintf(fullfilename, sizeof(fullfilename), "%s/%s",
                     fullpath, entry->d_name);
            debugs(47, 3, HERE << "Opening " << fullfilename);
            fd = file_open(fullfilename, O_RDONLY | O_BINARY);

            if (fd < 0) {
                int xerrno = errno;
                debugs(47, DBG_IMPORTANT, MYNAME << "error opening " << fullfilename << ": " << xstrerr(xerrno));
            } else
                ++store_open_disk_fd;

            continue;
        }

        if (td != NULL)
            closedir(td);

        td = NULL;

        in_dir = 0;

        if (sd->validL2(++curlvl2))
            continue;

        curlvl2 = 0;

        if (sd->validL1(++curlvl1))
            continue;

        curlvl1 = 0;

        done = 1;
    }

    *filn_p = fn;
    return fd;
}

bool
Fs::Ufs::RebuildState::error() const
{
    return false;
}

bool
Fs::Ufs::RebuildState::isDone() const
{
    return _done;
}

