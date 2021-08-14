/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_REQUEST_H
#define SQUID_IPC_REQUEST_H

#include "base/RefCount.h"
#include "base/TypeTraits.h"
#include "ipc/RequestId.h"

namespace Ipc
{

// TODO: Request and Response ought to have their own un/pack() methods instead
// of duplicating their functionality in derived classes. To avoid dependency
// loops between libipc and libmgr/libsnmp, fixing that requires extracting
// src/ipc/Coordinator and its friends into a new src/coordinator/ library.

/// IPC request
class Request: public RefCountable, public Interface
{
public:
    typedef RefCount<Request> Pointer;

public:
    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

public:
    int requestorId = 0; ///< kidId of the requestor; used for response destination
    RequestId requestId; ///< matches the request[or] with the response

protected:
    /// sender's constructor
    Request(const int aRequestorId, const RequestId aRequestId):
        requestorId(aRequestorId),
        requestId(aRequestId)
    {
    }

    /// recipient's constructor
    Request() = default;
};

} // namespace Ipc

#endif /* SQUID_IPC_REQUEST_H */

