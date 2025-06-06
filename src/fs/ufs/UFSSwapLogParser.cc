/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "debug/Stream.h"
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
    bool ReadRecord(StoreSwapLogData &swapData) override {
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
    bool ReadRecord(StoreSwapLogData &swapData) override {
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
        return nullptr;

    if (header.op != SWAP_LOG_VERSION) {
        debugs(47, DBG_IMPORTANT, "Old swap file detected...");
        fseek(fp, 0, SEEK_SET);
        return new UFSSwapLogParser_v1_32bs(fp); // Um. 32-bits except time_t, and can't determine that.
    }

    debugs(47, 2, "Swap file version: " << header.version);

    if (header.version == 1) {
        if (fseek(fp, header.record_size, SEEK_SET) != 0)
            return nullptr;

        debugs(47, DBG_IMPORTANT, "ERROR: Rejecting swap file v1 to avoid cache " <<
               "index corruption. Forcing a full cache index rebuild. " <<
               "See Squid bug #3441.");
        return nullptr;
    }

    if (header.version >= 2) {
        if (!header.sane()) {
            debugs(47, DBG_IMPORTANT, "ERROR: Corrupted v" << header.version <<
                   " swap file header.");
            return nullptr;
        }

        if (fseek(fp, header.record_size, SEEK_SET) != 0)
            return nullptr;

        if (header.version == 2)
            return new UFSSwapLogParser_v2(fp);
    }

    // TODO: v3: write to disk in network-order bytes for the larger fields?

    debugs(47, DBG_IMPORTANT, "ERROR: Unknown swap file version: " << header.version);
    return nullptr;
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

