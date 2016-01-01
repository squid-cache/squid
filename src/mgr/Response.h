/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_RESPONSE_H
#define SQUID_MGR_RESPONSE_H

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
    Response(unsigned int aRequestId, Action::Pointer anAction = NULL);

    explicit Response(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()

    /* Ipc::Response API */
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual Ipc::Response::Pointer clone() const;

    bool hasAction() const; ///< whether response contain action object
    const Action& getAction() const; ///< returns action object

private:
    Response(const Response& response);

public:
    Action::Pointer action; ///< action relating to response
};

} // namespace Mgr

#endif /* SQUID_MGR_RESPONSE_H */

