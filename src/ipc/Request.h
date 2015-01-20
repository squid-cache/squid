/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_REQUEST_H
#define SQUID_IPC_REQUEST_H

#include "base/RefCount.h"
#include "ipc/forward.h"

namespace Ipc
{

/// IPC request
class Request: public RefCountable
{
public:
    typedef RefCount<Request> Pointer;

public:
    Request(int aRequestorId, unsigned int aRequestId):
        requestorId(aRequestorId), requestId(aRequestId) {}

    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

private:
    Request(const Request&); // not implemented
    Request& operator= (const Request&); // not implemented

public:
    int requestorId; ///< kidId of the requestor; used for response destination
    unsigned int requestId; ///< unique for sender; matches request w/ response
};

} // namespace Ipc

#endif /* SQUID_IPC_REQUEST_H */

