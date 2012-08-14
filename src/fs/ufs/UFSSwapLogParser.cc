/*
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

#include "squid.h"
#include "Debug.h"
#include "md5.h"
#include "StoreSwapLogData.h"
#include "swap_log_op.h"
#include "UFSSwapLogParser.h"

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/// Parse a swap header entry created on a system with 32-bit size_t and sfileno
/// this is typical of 32-bit systems without large file support
/// NP: SQUID_MD5_DIGEST_LENGTH is very risky still.
class UFSSwapLogParser_v1_32bs:public Fs::Ufs::UFSSwapLogParser
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
    UFSSwapLogParser_v1_32bs(FILE *fp):Fs::Ufs::UFSSwapLogParser(fp) {
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

/// swap.state v2 log parser
class UFSSwapLogParser_v2: public Fs::Ufs::UFSSwapLogParser
{
public:
    UFSSwapLogParser_v2(FILE *fp): Fs::Ufs::UFSSwapLogParser(fp) {
        record_size = sizeof(StoreSwapLogData);
    }
    bool ReadRecord(StoreSwapLogData &swapData) {
        assert(log);
        return fread(&swapData, sizeof(StoreSwapLogData), 1, log) == 1;
    }
};

Fs::Ufs::UFSSwapLogParser *
Fs::Ufs::UFSSwapLogParser::GetUFSSwapLogParser(FILE *fp)
{
    StoreSwapLogHeader header;

    assert(fp);

    if (fread(&header, sizeof(StoreSwapLogHeader), 1, fp) != 1)
        return NULL;

    if (header.op != SWAP_LOG_VERSION) {
        debugs(47, DBG_IMPORTANT, "Old swap file detected...");
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
            debugs(47, DBG_IMPORTANT, "Version 1 of swap file with LFS support detected... ");
            return new UFSSwapLogParser_v1(fp);
        }

        // which means we have a 3-way grid of permutations to import (yuck!)
        // 1) sfileno 32-bit / 64-bit  (64-bit was broken)
        // 2) time_t 32-bit / 64-bit
        // 3) size_t 32-bit / 64-bit  (32-bit was pre-LFS)

        // 32-bit systems...
        // only LFS (size_t) differs from baseline
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_32bs::StoreSwapLogDataOld)) {
            debugs(47, DBG_IMPORTANT, "Version 1 (32-bit) swap file without LFS support detected... ");
            return new UFSSwapLogParser_v1_32bs(fp);
        }
        // LFS (size_t) and timestamps (time_t) differs from baseline
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_32bst::StoreSwapLogDataOld)) {
            debugs(47, DBG_IMPORTANT, "Version 1 (32-bit) swap file with short timestamps and without LFS support detected... ");
            return new UFSSwapLogParser_v1_32bst(fp);
        }
        // No downgrade for 64-bit timestamps to 32-bit.

        // 64-bit systems
        // sfileno was 64-bit for a some builds
        if (header.record_size == sizeof(struct UFSSwapLogParser_v1_64bfn::StoreSwapLogDataOld)) {
            debugs(47, DBG_IMPORTANT, "Version 1 (64-bit) swap file with broken sfileno detected... ");
            return new UFSSwapLogParser_v1_64bfn(fp);
        }
        // NP: 64-bit system with 32-bit size_t/time_t are not handled.

        debugs(47, DBG_IMPORTANT, "WARNING: The swap file has wrong format!... ");
        debugs(47, DBG_IMPORTANT, "NOTE: Cannot safely downgrade caches to short (32-bit) timestamps.");
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

int
Fs::Ufs::UFSSwapLogParser::SwapLogEntries()
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
