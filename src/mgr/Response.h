/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_RESPONSE_H
#define SQUID_SRC_MGR_RESPONSE_H

#include "ipc/forward.h"
#include "ipc/Response.h"
#include "mgr/Action.h"

namespace Mgr
{

/// A response to Mgr::Request.
/// May carry strand action data to be aggregated with data from other strands.
class Response: public Ipc::Response
{
public:
    /// sender's constructor
    Response(Ipc::RequestId, Action::Pointer anAction = nullptr);

    explicit Response(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()

    /* Ipc::Response API */
    void pack(Ipc::TypedMsgHdr& msg) const override;
    Ipc::Response::Pointer clone() const override;

    bool hasAction() const; ///< whether response contain action object
    const Action& getAction() const; ///< returns action object

public:
    Action::Pointer action; ///< action relating to response
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_RESPONSE_H */

