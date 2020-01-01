/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#include "squid.h"
#include "MemBuf.h"
#include "store/Controller.h"
#include "store_rebuild.h"

#include <cstring>

#define STUB_API "stub_store_rebuild.cc"
#include "tests/STUB.h"

void storeRebuildProgress(int sd_index, int total, int sofar) STUB
bool storeRebuildParseEntry(MemBuf &, StoreEntry &, cache_key *, StoreRebuildData &, uint64_t) STUB_RETVAL(false)

void storeRebuildComplete(StoreRebuildData *)
{
    --StoreController::store_dirs_rebuilding;
}

bool
storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &)
{
    if (fd < 0)
        return false;

    assert(buf.hasSpace()); // caller must allocate
    // this stub simulates reading an empty entry
    memset(buf.space(), 0, buf.spaceSize());
    buf.appended(buf.spaceSize());
    return true;
}

