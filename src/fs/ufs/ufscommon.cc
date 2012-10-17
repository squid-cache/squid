/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "ufscommon.h"
#include "Store.h"
#include "fde.h"
#include "SquidTime.h"
#include "StoreMeta.h"
#include "Generic.h"
#include "StoreMetaUnpacker.h"
#include "RefCount.h"
#include "StoreSwapLogData.h"
#include "swap_log_op.h"


CBDATA_CLASS_INIT(RebuildState);

/// Parse a swap header entry created on a system with 32-bit size_t and sfileno
/// this is typical of 32-bit systems without large file support
/// NP: SQUID_MD5_DIGEST_LENGTH is very risky still.
class UFSSwapLogParser_v1_32bs:public UFSSwapLogParser
{
public:
    /// version 1 cache swap.state entry with 32-bit size_t (swap_file_sz)
    /// time_t an sfileno have no variation from the v1 baseline format
    struct StoreSwapLogDataOld {
        char op;
        sfileno swap_filen;
        time_t timestamp;
        time_t lastref;
        time_t expires;
        time_t lastmod;
        uint32_t swap_file_sz;
        uint16_t refcount;
        uint16_t flags;
        unsigned char key[SQUID_MD5_DIGEST_LENGTH];
    };
    UFSSwapLogParser_v1_32bs(FILE *fp):UFSSwapLogParser(fp) {
        record_size = sizeof(UFSSwapLogParser_v1_32bs::StoreSwapLogDataOld);
    }
    /// Convert the on-disk 32-bit format to our current format while reading
    bool ReadRecord(StoreSwapLogData &swapData) {
        UFSSwapLogParser_v1_32bs::StoreSwapLogDataOld readData;
        int bytes = sizeof(UFSSwapLogParser_v1_32bs::StoreSwapLogDataOld);

        assert(log);

        if (fread(&readData, bytes, 1, log) != 1) {
            return false;
        }
        swapData.op = readData.op;
        swapData.swap_filen = readData.swap_filen;
        swapData.timestamp = readData.timestamp;
        swapData.lastref = readData.lastref;
        swapData.expires = readData.expires;
        swapData.lastmod = readData.lastmod;
        swapData.swap_file_sz = readData.swap_file_sz;
        swapData.refcount = readData.refcount;
        swapData.flags = readData.flags;
        memcpy(swapData.key, readData.key, SQUID_MD5_DIGEST_LENGTH);
        return true;
    }
};

#if UNUSED_CODE
/// Parse a swap header entry created on a system with 32-bit size_t, time_t and sfileno
/// this is typical of 32-bit systems without large file support and with old kernels
/// NP: SQUID_MD5_DIGEST_LENGTH is very risky still.
class UFSSwapLogParser_v1_32bst:public UFSSwapLogParser
{
public:
    /// version 1 cache swap.state entry with 32-bit size_t (swap_file_sz)
    /// time_t also differs
    /// sfileno has no variation from the v1 baseline format
    struct StoreSwapLogDataOld {
        char op;
        sfileno swap_filen;
        int32_t timestamp;
        int32_t lastref;
        int32_t expires;
        int32_t lastmod;
        uint32_t swap_file_sz;
        uint16_t refcount;
        uint16_t flags;
        unsigned char key[SQUID_MD5_DIGEST_LENGTH];
    };
    UFSSwapLogParser_v1_32bst(FILE *fp):UFSSwapLogParser(fp) {
        record_size = sizeof(UFSSwapLogParser_v1_32bst::StoreSwapLogDataOld);
    }
    /// Convert the on-disk 32-bit format to our current format while reading
    bool ReadRecord(StoreSwapLogData &swapData) {
        UFSSwapLogParser_v1_32bst::StoreSwapLogDataOld readData;
        int bytes = sizeof(UFSSwapLogParser_v1_32bst::StoreSwapLogDataOld);

        assert(log);

        if (fread(&readData, bytes, 1, log) != 1) {
            return false;
        }
        swapData.op = readData.op;
        swapData.swap_filen = readData.swap_filen;
        swapData.timestamp = readData.timestamp;
        swapData.lastref = readData.lastref;
        swapData.expires = readData.expires;
        swapData.lastmod = readData.lastmod;
        swapData.swap_file_sz = readData.swap_file_sz;
        swapData.refcount = readData.refcount;
        swapData.flags = readData.flags;
        memcpy(swapData.key, readData.key, SQUID_MD5_DIGEST_LENGTH);
        return true;
    }
};

/// Parse a swap header entry created on a system with 64-bit size_t and sfileno
/// this is typical of 64-bit systems prior to this patch fixing sfileno to 32-bits
/// NP: SQUID_MD5_DIGEST_LENGTH is very risky still.
class UFSSwapLogParser_v1_64bfn:public UFSSwapLogParser
{
public:
    /// version 1 cache swap.state entry with 64-bit sfileno
    struct StoreSwapLogDataOld {
        char op;
        int64_t swap_filen;
        time_t timestamp;
        time_t lastref;
        time_t expires;
        time_t lastmod;
        uint64_t swap_file_sz;
        uint16_t refcount;
        uint16_t flags;
        unsigned char key[SQUID_MD5_DIGEST_LENGTH];
    };
    UFSSwapLogParser_v1_64bfn(FILE *fp):UFSSwapLogParser(fp) {
        record_size = sizeof(UFSSwapLogParser_v1_64bfn::StoreSwapLogDataOld);
    }
    /// Convert the on-disk 64-bit format to our current format while reading
    bool ReadRecord(StoreSwapLogData &swapData) {
        UFSSwapLogParser_v1_64bfn::StoreSwapLogDataOld readData;
        int bytes = sizeof(UFSSwapLogParser_v1_64bfn::StoreSwapLogDataOld);

        assert(log);

        if (fread(&readData, bytes, 1, log) != 1) {
            return false;
        }
        swapData.op = readData.op;
        if ((readData.swap_filen>>32) != 0) {
            fatalf("File ID on record is greater than maximum cache file ID.");
        }
        swapData.swap_filen = (int32_t)readData.swap_filen;
        swapData.timestamp = readData.timestamp;
        swapData.lastref = readData.lastref;
        swapData.expires = readData.expires;
        swapData.lastmod = readData.lastmod;
        swapData.swap_file_sz = readData.swap_file_sz;
        swapData.refcount = readData.refcount;
        swapData.flags = readData.flags;
        memcpy(swapData.key, readData.key, SQUID_MD5_DIGEST_LENGTH);
        return true;
    }
};

class UFSSwapLogParser_v1:public UFSSwapLogParser
{
public:
    UFSSwapLogParser_v1(FILE *fp):UFSSwapLogParser(fp) {
        record_size = sizeof(StoreSwapLogData);
    }
    bool ReadRecord(StoreSwapLogData &swapData);
};


bool UFSSwapLogParser_v1::ReadRecord(StoreSwapLogData &swapData)
{
    int bytes = sizeof(StoreSwapLogData);

    assert(log);

    if (fread(&swapData, bytes, 1, log) != 1) {
        return false;
    }
    return true;
}
#endif /* UNUSED_CODE */

/// swap.state v2 log parser
class UFSSwapLogParser_v2: public UFSSwapLogParser
{
public:
    UFSSwapLogParser_v2(FILE *fp): UFSSwapLogParser(fp) {
        record_size = sizeof(StoreSwapLogData);
    }
    bool ReadRecord(StoreSwapLogData &swapData) {
        assert(log);
        return fread(&swapData, sizeof(StoreSwapLogData), 1, log) == 1;
    }
};


UFSSwapLogParser *UFSSwapLogParser::GetUFSSwapLogParser(FILE *fp)
{
    StoreSwapLogHeader header;

    assert(fp);

    if (fread(&header, sizeof(StoreSwapLogHeader), 1, fp) != 1)
        return NULL;

    if (header.op != SWAP_LOG_VERSION) {
        debugs(47, 1, "Old swap file detected...");
        fseek(fp, 0, SEEK_SET);
        return new UFSSwapLogParser_v1_32bs(fp); // Um. 32-bits except time_t, and can't determine that.
    }

    debugs(47, 2, "Swap file version: " << header.version);

    if (header.version == 1) {
        if (fseek(fp, header.record_size, SEEK_SET) != 0)
            return NULL;

        debugs(47, DBG_IMPORTANT, "Rejecting swap file v1 to avoid cache " <<
               "index corruption. Forcing a full cache index rebuild. " <<
               "See Squid bug #3441.");
        return NULL;

#if UNUSED_CODE
        // baseline
        // 32-bit sfileno
        // native time_t (hopefully 64-bit)
        // 64-bit file size
        if (header.record_size == sizeof(StoreSwapLogData)) {
            debugs(47, 1, "Version 1 of swap file with LFS support detected... ");
            return new UFSSwapLogParser_v1(fp);
        }

        // which means we have a 3-way grid of permutations to import (yuck!)
        // 1) sfileno 32-bit / 64-bit  (64-bit was broken)
        // 2) time_t 32-bit / 64-bit
        // 3) size_t 32-bit / 64-bit  (32-bit was pre-LFS)

        // 32-bit systems...
        // only LFS (size_t) differs from baseline
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_32bs::StoreSwapLogDataOld)) {
            debugs(47, 1, "Version 1 (32-bit) swap file without LFS support detected... ");
            return new UFSSwapLogParser_v1_32bs(fp);
        }
        // LFS (size_t) and timestamps (time_t) differs from baseline
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_32bst::StoreSwapLogDataOld)) {
            debugs(47, 1, "Version 1 (32-bit) swap file with short timestamps and without LFS support detected... ");
            return new UFSSwapLogParser_v1_32bst(fp);
        }
        // No downgrade for 64-bit timestamps to 32-bit.

        // 64-bit systems
        // sfileno was 64-bit for a some builds
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_64bfn::StoreSwapLogDataOld)) {
            debugs(47, 1, "Version 1 (64-bit) swap file with broken sfileno detected... ");
            return new UFSSwapLogParser_v1_64bfn(fp);
        }
        // NP: 64-bit system with 32-bit size_t/time_t are not handled.

        debugs(47, 1, "WARNING: The swap file has wrong format!... ");
        debugs(47, 1, "NOTE: Cannot safely downgrade caches to short (32-bit) timestamps.");
        return NULL;
#endif
    }

    if (header.version >= 2) {
        if (!header.sane()) {
            debugs(47, DBG_IMPORTANT, "ERROR: Corrupted v" << header.version <<
                   " swap file header.");
            return NULL;
        }

        if (fseek(fp, header.record_size, SEEK_SET) != 0)
            return NULL;

        if (header.version == 2)
            return new UFSSwapLogParser_v2(fp);
    }

    // TODO: v3: write to disk in network-order bytes for the larger fields?

    debugs(47, DBG_IMPORTANT, "Unknown swap file version: " << header.version);
    return NULL;
}

int UFSSwapLogParser::SwapLogEntries()
{
    struct stat sb;

    if (log_entries >= 0)
        return log_entries;

    if (log && record_size && 0 == fstat(fileno(log), &sb)) {
        log_entries = sb.st_size/record_size;
        return log_entries;
    }

    return 0;
}




RebuildState::RebuildState (RefCount<UFSSwapDir> aSwapDir) : sd (aSwapDir),LogParser(NULL), e(NULL), fromLog(true), _done (false)
{
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use commonUfsDirRebuildFromSwapLog(), otherwise we'll
     * use commonUfsDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    int clean = 0;
    int zeroLengthLog = 0;
    FILE *fp = sd->openTmpSwapLog(&clean, &zeroLengthLog);

    if (fp && !zeroLengthLog)
        LogParser = UFSSwapLogParser::GetUFSSwapLogParser(fp);

    if (LogParser == NULL ) {
        fromLog = false;

        if (fp != NULL)
            fclose(fp);

    } else {
        fromLog = true;
        flags.clean = (unsigned int) clean;
    }

    if (!clean)
        flags.need_to_validate = 1;

    debugs(47, DBG_IMPORTANT, "Rebuilding storage in " << sd->path << " (" <<
           (clean ? "clean log" : (LogParser ? "dirty log" : "no log")) << ")");
}

RebuildState::~RebuildState()
{
    sd->closeTmpSwapLog();

    if (LogParser)
        delete LogParser;
}

void
RebuildState::RebuildStep(void *data)
{
    RebuildState *rb = (RebuildState *)data;
    rb->rebuildStep();

    if (!rb->isDone())
        eventAdd("storeRebuild", RebuildStep, rb, 0.01, 1);
    else {
        -- StoreController::store_dirs_rebuilding;
        storeRebuildComplete(&rb->counts);
        delete rb;
    }
}

/// load entries from swap.state or files until we run out of entries or time
void
RebuildState::rebuildStep()
{
    currentEntry(NULL);

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
RebuildState::rebuildFromDirectory()
{
    cache_key key[SQUID_MD5_DIGEST_LENGTH];

    struct stat sb;
    int fd = -1;
    assert(this != NULL);
    debugs(47, 3, "commonUfsDirRebuildFromDirectory: DIR #" << sd->index);

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
        debugs(47, 1, "commonUfsDirRebuildFromDirectory: fstat(FD " << fd << "): " << xstrerror());
        file_close(fd);
        --store_open_disk_fd;
        fd = -1;
        return;
    }

    MemBuf buf;
    buf.init(SM_PAGE_SIZE, SM_PAGE_SIZE);
    if (!storeRebuildLoadEntry(fd, sd->index, buf, counts))
        return;

    StoreEntry tmpe;
    const bool loaded = storeRebuildParseEntry(buf, tmpe, key, counts,
                        (int64_t)sb.st_size);

    file_close(fd);
    --store_open_disk_fd;
    fd = -1;

    if (!loaded) {
        // XXX: shouldn't this be a call to commonUfsUnlink?
        sd->unlinkFile(filn); // should we unlink in all failure cases?
        return;
    }

    if (!storeRebuildKeepEntry(tmpe, key, counts))
        return;

    ++counts.objcount;
    // tmpe.dump(5);
    currentEntry(sd->addDiskRestore(key,
                                    filn,
                                    tmpe.swap_file_sz,
                                    tmpe.expires,
                                    tmpe.timestamp,
                                    tmpe.lastref,
                                    tmpe.lastmod,
                                    tmpe.refcount,	/* refcount */
                                    tmpe.flags,		/* flags */
                                    (int) flags.clean));
    storeDirSwapLog(currentEntry(), SWAP_LOG_ADD);
}

StoreEntry *
RebuildState::currentEntry() const
{
    return e;
}

void
RebuildState::currentEntry(StoreEntry *newValue)
{
    e = newValue;
}

/// process one swap log entry
void
RebuildState::rebuildFromSwapLog()
{
    StoreSwapLogData swapData;

    if (LogParser->ReadRecord(swapData) != 1) {
        debugs(47, 1, "Done reading " << sd->path << " swaplog (" << n_read << " entries)");
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

    debugs(47, 3, "commonUfsDirRebuildFromSwapLog: " <<
           swap_log_op_str[(int) swapData.op]  << " " <<
           storeKeyText(swapData.key)  << " "<< std::setfill('0') <<
           std::hex << std::uppercase << std::setw(8) <<
           swapData.swap_filen);

    if (swapData.op == SWAP_LOG_ADD) {
        (void) 0;
    } else if (swapData.op == SWAP_LOG_DEL) {
        /* Delete unless we already have a newer copy anywhere in any store */
        /* this needs to become
         * 1) unpack url
         * 2) make synthetic request with headers ?? or otherwise search
         * for a matching object in the store
         * TODO FIXME change to new async api
         */
        currentEntry (Store::Root().get(swapData.key));

        if (currentEntry() != NULL && swapData.lastref >= e->lastref) {
            undoAdd();
            --counts.objcount;
            ++counts.cancelcount;
        }
        return;
    } else {
        const double
        x = ::log(static_cast<double>(++counts.bad_log_op)) / ::log(10.0);

        if (0.0 == x - (double) (int) x)
            debugs(47, 1, "WARNING: " << counts.bad_log_op << " invalid swap log entries found");

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

    /* this needs to become
     * 1) unpack url
     * 2) make synthetic request with headers ?? or otherwise search
     * for a matching object in the store
     * TODO FIXME change to new async api
     */
    currentEntry (Store::Root().get(swapData.key));

    int used;			/* is swapfile already in use? */

    used = sd->mapBitTest(swapData.swap_filen);

    /* If this URL already exists in the cache, does the swap log
     * appear to have a newer entry?  Compare 'lastref' from the
     * swap log to e->lastref. */
    /* is the log entry newer than current entry? */
    int disk_entry_newer = currentEntry() ? (swapData.lastref > currentEntry()->lastref ? 1 : 0) : 0;

    if (used && !disk_entry_newer) {
        /* log entry is old, ignore it */
        ++counts.clashcount;
        return;
    } else if (used && currentEntry() && currentEntry()->swap_filen == swapData.swap_filen && currentEntry()->swap_dirn == sd->index) {
        /* swapfile taken, same URL, newer, update meta */

        if (currentEntry()->store_status == STORE_OK) {
            currentEntry()->lastref = swapData.timestamp;
            currentEntry()->timestamp = swapData.timestamp;
            currentEntry()->expires = swapData.expires;
            currentEntry()->lastmod = swapData.lastmod;
            currentEntry()->flags = swapData.flags;
            currentEntry()->refcount += swapData.refcount;
            sd->dereference(*currentEntry(), false);
        } else {
            debug_trap("commonUfsDirRebuildFromSwapLog: bad condition");
            debugs(47, 1, "\tSee " << __FILE__ << ":" << __LINE__);
        }
        return;
    } else if (used) {
        /* swapfile in use, not by this URL, log entry is newer */
        /* This is sorta bad: the log entry should NOT be newer at this
         * point.  If the log is dirty, the filesize check should have
         * caught this.  If the log is clean, there should never be a
         * newer entry. */
        debugs(47, 1, "WARNING: newer swaplog entry for dirno " <<
               sd->index  << ", fileno "<< std::setfill('0') << std::hex <<
               std::uppercase << std::setw(8) << swapData.swap_filen);

        /* I'm tempted to remove the swapfile here just to be safe,
         * but there is a bad race condition in the NOVM version if
         * the swapfile has recently been opened for writing, but
         * not yet opened for reading.  Because we can't map
         * swapfiles back to StoreEntrys, we don't know the state
         * of the entry using that file.  */
        /* We'll assume the existing entry is valid, probably because
         * were in a slow rebuild and the the swap file number got taken
         * and the validation procedure hasn't run. */
        assert(flags.need_to_validate);
        ++counts.clashcount;
        return;
    } else if (currentEntry() && !disk_entry_newer) {
        /* key already exists, current entry is newer */
        /* keep old, ignore new */
        ++counts.dupcount;
        return;
    } else if (currentEntry()) {
        /* key already exists, this swapfile not being used */
        /* junk old, load new */
        undoAdd();
        --counts.objcount;
        ++counts.dupcount;
    } else {
        /* URL doesnt exist, swapfile not in use */
        /* load new */
        (void) 0;
    }

    ++counts.objcount;

    currentEntry(sd->addDiskRestore(swapData.key,
                                    swapData.swap_filen,
                                    swapData.swap_file_sz,
                                    swapData.expires,
                                    swapData.timestamp,
                                    swapData.lastref,
                                    swapData.lastmod,
                                    swapData.refcount,
                                    swapData.flags,
                                    (int) flags.clean));

    storeDirSwapLog(currentEntry(), SWAP_LOG_ADD);
}

/// undo the effects of adding an entry in rebuildFromSwapLog()
void
RebuildState::undoAdd()
{
    StoreEntry *added = currentEntry();
    assert(added);
    currentEntry(NULL);

    // TODO: Why bother with these two if we are going to release?!
    added->expireNow();
    added->releaseRequest();

    if (added->swap_filen > -1) {
        UFSSwapDir *sde = dynamic_cast<UFSSwapDir *>(INDEXSD(added->swap_dirn));
        assert(sde);
        sde->undoAddDiskRestore(added);
    }

    added->release();
}

int
RebuildState::getNextFile(sfileno * filn_p, int *size)
{
    int fd = -1;
    int dirs_opened = 0;
    debugs(47, 3, "commonUfsDirGetNextFile: flag=" << flags.init  << ", " <<
           sd->index  << ": /"<< std::setfill('0') << std::hex <<
           std::uppercase << std::setw(2) << curlvl1  << "/" << std::setw(2) <<
           curlvl2);

    if (done)
        return -2;

    while (fd < 0 && done == 0) {
        fd = -1;

        if (0 == flags.init) {	/* initialize, open first file */
            done = 0;
            curlvl1 = 0;
            curlvl2 = 0;
            in_dir = 0;
            flags.init = 1;
            assert(Config.cacheSwap.n_configured > 0);
        }

        if (0 == in_dir) {	/* we need to read in a new directory */
            snprintf(fullpath, MAXPATHLEN, "%s/%02X/%02X",
                     sd->path,
                     curlvl1, curlvl2);

            if (dirs_opened)
                return -1;

            td = opendir(fullpath);

            ++dirs_opened;

            if (td == NULL) {
                debugs(47, 1, "commonUfsDirGetNextFile: opendir: " << fullpath << ": " << xstrerror());
            } else {
                entry = readdir(td);	/* skip . and .. */
                entry = readdir(td);

                if (entry == NULL && errno == ENOENT)
                    debugs(47, 1, "commonUfsDirGetNextFile: directory does not exist!.");
                debugs(47, 3, "commonUfsDirGetNextFile: Directory " << fullpath);
            }
        }

        if (td != NULL && (entry = readdir(td)) != NULL) {
            ++in_dir;

            if (sscanf(entry->d_name, "%x", &fn) != 1) {
                debugs(47, 3, "commonUfsDirGetNextFile: invalid " << entry->d_name);
                continue;
            }

            if (!UFSSwapDir::FilenoBelongsHere(fn, sd->index, curlvl1, curlvl2)) {
                debugs(47, 3, "commonUfsDirGetNextFile: "<< std::setfill('0') <<
                       std::hex << std::uppercase << std::setw(8) << fn  <<
                       " does not belong in " << std::dec << sd->index  << "/" <<
                       curlvl1  << "/" << curlvl2);

                continue;
            }

            if (sd->mapBitTest(fn)) {
                debugs(47, 3, "commonUfsDirGetNextFile: Locked, continuing with next.");
                continue;
            }

            snprintf(fullfilename, MAXPATHLEN, "%s/%s",
                     fullpath, entry->d_name);
            debugs(47, 3, "commonUfsDirGetNextFile: Opening " << fullfilename);
            fd = file_open(fullfilename, O_RDONLY | O_BINARY);

            if (fd < 0)
                debugs(47, 1, "commonUfsDirGetNextFile: " << fullfilename << ": " << xstrerror());
            else
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
RebuildState::error() const
{
    return false;
}

bool
RebuildState::isDone() const
{
    return _done;
}

StoreEntry *
RebuildState::currentItem()
{
    return currentEntry();
}

#if !_USE_INLINE_
#include "ufscommon.cci"
#endif
