/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_FS_ROCK_ROCKIOREQUESTS_H
#define SQUID_SRC_STORE_FS_ROCK_ROCKIOREQUESTS_H

#if USE_STORE_FS_ROCK

#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "store/fs/rock/forward.h"
#include "store/fs/rock/RockIoState.h"

class DiskFile;

namespace Rock
{

class ReadRequest: public ::ReadRequest
{
    CBDATA_CLASS(ReadRequest);

public:
    ReadRequest(const ::ReadRequest &, const IoState::Pointer &, const IoXactionId);
    IoState::Pointer sio;

    /// identifies this read transaction for the requesting IoState
    IoXactionId id;
};

class WriteRequest: public ::WriteRequest
{
    CBDATA_CLASS(WriteRequest);

public:
    WriteRequest(const ::WriteRequest &, const IoState::Pointer &, const IoXactionId);
    IoState::Pointer sio;

    /* We own these two reserved slots until SwapDir links them into the map. */

    /// slot that will point to sidCurrent in the cache_dir map
    SlotId sidPrevious;

    /// slot being written using this write request
    SlotId sidCurrent;

    /// identifies this write transaction for the requesting IoState
    IoXactionId id;

    /// whether this is the last request for the entry
    bool eof;
};

} // namespace Rock

#endif /* USE_STORE_FS_ROCK */
#endif /* SQUID_SRC_STORE_FS_ROCK_ROCKIOREQUESTS_H */
