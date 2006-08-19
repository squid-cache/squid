/*
 * $Id: ufscommon.cc,v 1.6 2006/08/19 12:31:24 robertc Exp $
 * vim: set et : 
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

#include "ufscommon.h"
#include "Store.h"
#include "fde.h"
#include "StoreMeta.h"
#include "Generic.h"
#include "StoreMetaUnpacker.h"
#include "RefCount.h"
#include "StoreSwapLogData.h"

CBDATA_CLASS_INIT(RebuildState);

RebuildState::RebuildState (RefCount<UFSSwapDir> aSwapDir) : sd (aSwapDir), e(NULL), fromLog(true), _done (false)
{
    speed = opt_foreground_rebuild ? 1 << 30 : 50;
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use commonUfsDirRebuildFromSwapLog(), otherwise we'll
     * use commonUfsDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    int clean = 0;
    int zeroLengthLog = 0;
    FILE *fp = sd->openTmpSwapLog(&clean, &zeroLengthLog);

    if (fp == NULL || zeroLengthLog) {
        fromLog = false;

        if (fp != NULL)
            fclose(fp);

    } else {
        fromLog = true;
        log = fp;
        flags.clean = (unsigned int) clean;
    }

    if (!clean)
        flags.need_to_validate = 1;

    debug(47, 1) ("Rebuilding storage in %s (%s)\n",
                  sd->path, clean ? "CLEAN" : "DIRTY");
}

RebuildState::~RebuildState()
{
    sd->closeTmpSwapLog();
}

void
RebuildState::RebuildStep(void *data)
{
    RebuildState *rb = (RebuildState *)data;
    rb->rebuildStep();

    if (!rb->isDone())
        eventAdd("storeRebuild", RebuildStep, rb, 0.0, 1);
    else {
        StoreController::store_dirs_rebuilding--;
        storeRebuildComplete(&rb->counts);
        delete rb;
    }
}

void
RebuildState::rebuildStep()
{
    if (fromLog)
        rebuildFromSwapLog();
    else
        rebuildFromDirectory();
}

struct InitStoreEntry : public unary_function<StoreMeta, void>
{
    InitStoreEntry(StoreEntry *anEntry, cache_key *aKey):what(anEntry),index(aKey){}

    void operator()(StoreMeta const &x)
    {
        switch (x.getType()) {

        case STORE_META_KEY:
            assert(x.length == MD5_DIGEST_CHARS);
            xmemcpy(index, x.value, MD5_DIGEST_CHARS);
            break;

        case STORE_META_STD:
            assert(x.length == STORE_HDR_METASIZE);
            xmemcpy(&what->timestamp, x.value, STORE_HDR_METASIZE);
            break;

        default:
            break;
        }
    }

    StoreEntry *what;
    cache_key *index;
};

void
RebuildState::rebuildFromDirectory()
{
    LOCAL_ARRAY(char, hdr_buf, SM_PAGE_SIZE);
    currentEntry(NULL);
    StoreEntry tmpe;
    cache_key key[MD5_DIGEST_CHARS];

    struct stat sb;
    int swap_hdr_len;
    int fd = -1;
    StoreMeta *tlv_list;
    assert(this != NULL);
    debug(47, 3) ("commonUfsDirRebuildFromDirectory: DIR #%d\n", sd->index);

    for (int count = 0; count < speed; count++) {
        assert(fd == -1);
        sfileno filn = 0;
        int size;
        fd = getNextFile(&filn, &size);

        if (fd == -2) {
            debug(47, 1) ("Done scanning %s swaplog (%d entries)\n",
                          sd->path, n_read);
            _done = true;
            return;
        } else if (fd < 0) {
            continue;
        }

        assert(fd > -1);
        /* lets get file stats here */

        if (fstat(fd, &sb) < 0) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: fstat(FD %d): %s\n",
                          fd, xstrerror());
            file_close(fd);
            store_open_disk_fd--;
            fd = -1;
            continue;
        }

        if ((++counts.scancount & 0xFFFF) == 0)
            debug(47, 3) ("  %s %7d files opened so far.\n",
                          sd->path, counts.scancount);

        debug(47, 9) ("file_in: fd=%d %08X\n", fd, filn);

        statCounter.syscalls.disk.reads++;

        int len;

        if ((len = FD_READ_METHOD(fd, hdr_buf, SM_PAGE_SIZE)) < 0) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: read(FD %d): %s\n",
                          fd, xstrerror());
            file_close(fd);
            store_open_disk_fd--;
            fd = -1;
            continue;
        }

        file_close(fd);
        store_open_disk_fd--;
        fd = -1;
        swap_hdr_len = 0;
#if USE_TRUNCATE

        if (sb.st_size == 0)
            continue;

#endif

        StoreMetaUnpacker aBuilder(hdr_buf, len, &swap_hdr_len);

        if (!aBuilder.isBufferSane()) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: Swap data buffer length is not sane.\n");
            /* XXX shouldn't this be a call to commonUfsUnlink ? */
            sd->unlinkFile ( filn);
            continue;
        }

        tlv_list = aBuilder.createStoreMeta ();

        if (tlv_list == NULL) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: failed to get meta data\n");
            /* XXX shouldn't this be a call to commonUfsUnlink ? */
            sd->unlinkFile (filn);
            continue;
        }

        debug(47, 3) ("commonUfsDirRebuildFromDirectory: successful swap meta unpacking\n");
        memset(key, '\0', MD5_DIGEST_CHARS);
        memset(&tmpe, '\0', sizeof(StoreEntry));
        InitStoreEntry visitor(&tmpe, key);
        for_each(*tlv_list, visitor);
        storeSwapTLVFree(tlv_list);
        tlv_list = NULL;

        if (storeKeyNull(key)) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: NULL key\n");
            sd->unlinkFile(filn);
            continue;
        }

        tmpe.key = key;
        /* check sizes */

        if (tmpe.swap_file_sz == 0) {
            tmpe.swap_file_sz = (size_t) sb.st_size;
        } else if (tmpe.swap_file_sz == (size_t)(sb.st_size - swap_hdr_len)) {
            tmpe.swap_file_sz = (size_t) sb.st_size;
        } else if (tmpe.swap_file_sz != (size_t)sb.st_size) {
            debug(47, 1) ("commonUfsDirRebuildFromDirectory: SIZE MISMATCH %ld!=%ld\n",
                          (long int) tmpe.swap_file_sz, (long int) sb.st_size);
            sd->unlinkFile(filn);
            continue;
        }

        if (EBIT_TEST(tmpe.flags, KEY_PRIVATE)) {
            sd->unlinkFile(filn);
            counts.badflags++;
            continue;
        }

        /* this needs to become
         * 1) unpack url
         * 2) make synthetic request with headers ?? or otherwise search
         * for a matching object in the store
         * TODO FIXME change to new async api
         * TODO FIXME I think there is a race condition here with the
         * async api :
         * store A reads in object foo, searchs for it, and finds nothing.
         * store B reads in object foo, searchs for it, finds nothing.
         * store A gets called back with nothing, so registers the object
         * store B gets called back with nothing, so registers the object,
         * which will conflict when the in core index gets around to scanning
         * store B.
         *
         * this suggests that rather than searching for duplicates, the 
         * index rebuild should just assume its the most recent accurate
         * store entry and whoever indexes the stores handles duplicates.
         */
        e = Store::Root().get(key);

        if (e && e->lastref >= tmpe.lastref) {
            /* key already exists, current entry is newer */
            /* keep old, ignore new */
            counts.dupcount++;
            continue;
        } else if (NULL != e) {
            /* URL already exists, this swapfile not being used */
            /* junk old, load new */
            e->release();	/* release old entry */
            counts.dupcount++;
        }

        counts.objcount++;
        storeEntryDump(&tmpe, 5);
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

void
RebuildState::rebuildFromSwapLog()
{
    currentEntry (NULL);
    double x;
    /* load a number of objects per invocation */

    for (int count = 0; count < speed; count++) {
        StoreSwapLogData swapData;
        size_t ss = sizeof(StoreSwapLogData);

        if (fread(&swapData, ss, 1, log) != 1) {
            debug(47, 1) ("Done reading %s swaplog (%d entries)\n",
                          sd->path, n_read);
            fclose(log);
            log = NULL;
            _done = true;
            return;
        }

        n_read++;

        if (swapData.op <= SWAP_LOG_NOP)
            continue;

        if (swapData.op >= SWAP_LOG_MAX)
            continue;

        /*
         * BC: during 2.4 development, we changed the way swap file
         * numbers are assigned and stored.  The high 16 bits used
         * to encode the SD index number.  There used to be a call
         * to storeDirProperFileno here that re-assigned the index 
         * bits.  Now, for backwards compatibility, we just need
         * to mask it off.
         */
        swapData.swap_filen &= 0x00FFFFFF;

        debug(47, 3) ("commonUfsDirRebuildFromSwapLog: %s %s %08X\n",
                      swap_log_op_str[(int) swapData.op],
                      storeKeyText(swapData.key),
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

            if (currentEntry() != NULL && swapData.lastref > e->lastref) {
                /*
                 * Make sure we don't unlink the file, it might be
                 * in use by a subsequent entry.  Also note that
                 * we don't have to subtract from store_swap_size
                 * because adding to store_swap_size happens in
                 * the cleanup procedure.
                 */
                storeExpireNow(currentEntry());
                storeReleaseRequest(currentEntry());

                if (currentEntry()->swap_filen > -1) {
                    UFSSwapDir *sdForThisEntry = dynamic_cast<UFSSwapDir *>(INDEXSD(currentEntry()->swap_dirn));
                    assert (sdForThisEntry);
                    sdForThisEntry->replacementRemove(currentEntry());
                    sdForThisEntry->mapBitReset(currentEntry()->swap_filen);
                    currentEntry()->swap_filen = -1;
                    currentEntry()->swap_dirn = -1;
                }

                currentEntry()->release();
                counts.objcount--;
                counts.cancelcount++;
            }

            continue;
        } else {
            x = ::log(static_cast<double>(++counts.bad_log_op)) / ::log(10.0);

            if (0.0 == x - (double) (int) x)
                debug(47, 1) ("WARNING: %d invalid swap log entries found\n",
                              counts.bad_log_op);

            counts.invalid++;

            continue;
        }

        if ((++counts.scancount & 0xFFF) == 0) {

            struct stat sb;

            if (0 == fstat(fileno(log), &sb))
                storeRebuildProgress(sd->index,
                                     (int) sb.st_size / ss, n_read);
        }

        if (!sd->validFileno(swapData.swap_filen, 0)) {
            counts.invalid++;
            continue;
        }

        if (EBIT_TEST(swapData.flags, KEY_PRIVATE)) {
            counts.badflags++;
            continue;
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
            counts.clashcount++;
            continue;
        } else if (used && currentEntry() && currentEntry()->swap_filen == swapData.swap_filen && currentEntry()->swap_dirn == sd->index) {
            /* swapfile taken, same URL, newer, update meta */

            if (currentEntry()->store_status == STORE_OK) {
                currentEntry()->lastref = swapData.timestamp;
                currentEntry()->timestamp = swapData.timestamp;
                currentEntry()->expires = swapData.expires;
                currentEntry()->lastmod = swapData.lastmod;
                currentEntry()->flags = swapData.flags;
                currentEntry()->refcount += swapData.refcount;
                sd->dereference(*currentEntry());
            } else {
                debug_trap("commonUfsDirRebuildFromSwapLog: bad condition");
                debug(47, 1) ("\tSee %s:%d\n", __FILE__, __LINE__);
            }

            continue;
        } else if (used) {
            /* swapfile in use, not by this URL, log entry is newer */
            /* This is sorta bad: the log entry should NOT be newer at this
             * point.  If the log is dirty, the filesize check should have
             * caught this.  If the log is clean, there should never be a
             * newer entry. */
            debug(47, 1) ("WARNING: newer swaplog entry for dirno %d, fileno %08X\n",
                          sd->index, swapData.swap_filen);
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
            counts.clashcount++;
            continue;
        } else if (currentEntry() && !disk_entry_newer) {
            /* key already exists, current entry is newer */
            /* keep old, ignore new */
            counts.dupcount++;
            continue;
        } else if (currentEntry()) {
            /* key already exists, this swapfile not being used */
            /* junk old, load new */
            storeExpireNow(currentEntry());
            storeReleaseRequest(currentEntry());

            if (currentEntry()->swap_filen > -1) {
                UFSSwapDir *sdForThisEntry = dynamic_cast<UFSSwapDir *>(INDEXSD(currentEntry()->swap_dirn));
                sdForThisEntry->replacementRemove(currentEntry());
                /* Make sure we don't actually unlink the file */
                sdForThisEntry->mapBitReset(currentEntry()->swap_filen);
                currentEntry()->swap_filen = -1;
                currentEntry()->swap_dirn = -1;
            }

            currentEntry()->release();
            counts.dupcount++;
        } else {
            /* URL doesnt exist, swapfile not in use */
            /* load new */
            (void) 0;
        }

        /* update store_swap_size */
        counts.objcount++;

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

}

int
RebuildState::getNextFile(sfileno * filn_p, int *size)
{
    int fd = -1;
    int dirs_opened = 0;
    debug(47, 3) ("commonUfsDirGetNextFile: flag=%d, %d: /%02X/%02X\n",
                  flags.init,
                  sd->index,
                  curlvl1,
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
            snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X",
                     sd->path,
                     curlvl1, curlvl2);

            if (dirs_opened)
                return -1;

            td = opendir(fullpath);

            dirs_opened++;

            if (td == NULL) {
                debug(47, 1) ("commonUfsDirGetNextFile: opendir: %s: %s\n",
                              fullpath, xstrerror());
            } else {
                entry = readdir(td);	/* skip . and .. */
                entry = readdir(td);

                if (entry == NULL && errno == ENOENT)
                    debug(47, 1) ("commonUfsDirGetNextFile: directory does not exist!.\n");

                debug(47, 3) ("commonUfsDirGetNextFile: Directory %s\n", fullpath);
            }
        }

        if (td != NULL && (entry = readdir(td)) != NULL) {
            in_dir++;

            if (sscanf(entry->d_name, "%x", &fn) != 1) {
                debug(47, 3) ("commonUfsDirGetNextFile: invalid %s\n",
                              entry->d_name);
                continue;
            }

            if (!UFSSwapDir::FilenoBelongsHere(fn, sd->index, curlvl1, curlvl2)) {
                debug(47, 3) ("commonUfsDirGetNextFile: %08X does not belong in %d/%d/%d\n",
                              fn, sd->index, curlvl1, curlvl2);
                continue;
            }

            if (sd->mapBitTest(fn)) {
                debug(47, 3) ("commonUfsDirGetNextFile: Locked, continuing with next.\n");
                continue;
            }

            snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%s",
                     fullpath, entry->d_name);
            debug(47, 3) ("commonUfsDirGetNextFile: Opening %s\n", fullfilename);
            fd = file_open(fullfilename, O_RDONLY | O_BINARY);

            if (fd < 0)
                debug(47, 1) ("commonUfsDirGetNextFile: %s: %s\n", fullfilename, xstrerror());
            else
                store_open_disk_fd++;

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

void
RebuildState::next(void (callback)(void *cbdata), void *cbdata)
{
    /* for now, we don't cache at all */
    speed = 1;
    currentEntry(NULL);

    while (!isDone() && currentEntry() == NULL)
        rebuildStep();

    callback(cbdata);
}

bool
RebuildState::next()
{
    return false;
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

#ifndef _USE_INLINE_
#include "ufscommon.cci"
#endif
