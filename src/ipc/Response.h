/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_RESPONSE_H
#define SQUID_IPC_RESPONSE_H

#include "base/RefCount.h"
#include "base/TypeTraits.h"
#include "ipc/forward.h"
#include "ipc/QuestionerId.h"

namespace Ipc
{

/// A response to Ipc::Request.
class Response: public RefCountable, public Interface
{
public:
    typedef RefCount<Response> Pointer;

public:
    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

    /// for Mine() tests
    QuestionerId intendedRecepient() const { return requestId.questioner(); }

public:
    RequestId requestId; ///< the ID of the request we are responding to

protected:
    /// sender's constructor
    explicit Response(const RequestId aRequestId): requestId(aRequestId) {}

    /// recipient's constructor
    Response() = default;
};

} // namespace Ipc

#endif /* SQUID_IPC_RESPONSE_H */

