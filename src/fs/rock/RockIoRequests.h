/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_IO_REQUESTS_H
#define SQUID_FS_ROCK_IO_REQUESTS_H

#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockIoState.h"

class DiskFile;

namespace Rock
{

/// \ingroup Rock
class ReadRequest: public ::ReadRequest
{
public:
    ReadRequest(const ::ReadRequest &base, const IoState::Pointer &anSio);
    IoState::Pointer sio;

private:
    CBDATA_CLASS2(ReadRequest);
};

/// \ingroup Rock
class WriteRequest: public ::WriteRequest
{
public:
    WriteRequest(const ::WriteRequest &base, const IoState::Pointer &anSio);
    IoState::Pointer sio;

    /// slot being written using this write request
    SlotId sidCurrent;

    /// allocated next slot (negative if we are writing the last slot)
    SlotId sidNext;

    /// whether this is the last request for the entry
    bool eof;

private:
    CBDATA_CLASS2(WriteRequest);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_IO_REQUESTS_H */

