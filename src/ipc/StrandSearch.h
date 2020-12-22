/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_STRAND_SEARCH_H
#define SQUID_IPC_STRAND_SEARCH_H

#include "ipc/forward.h"
#include "ipc/StrandCoord.h"
#include "SquidString.h"

namespace Ipc
{

/// asynchronous strand search request
class StrandSearchRequest
{
public:
    StrandSearchRequest();
    explicit StrandSearchRequest(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int requestorId; ///< sender-provided return address
    String tag; ///< set when looking for a matching StrandCoord::tag
};

/// an IPC message with coordinates and 'indexed' status of the found strand
class StrandSearchResponse
{
public:
    explicit StrandSearchResponse(bool isIndexed, const StrandCoord &);
    explicit StrandSearchResponse(const TypedMsgHdr &);
    void pack(TypedMsgHdr &) const;

    bool indexed; ///< whether the found strand is 'indexed'
    StrandCoord strand; ///< the found strand coordinates
};

} // namespace Ipc;

#endif /* SQUID_IPC_STRAND_SEARCH_H */

