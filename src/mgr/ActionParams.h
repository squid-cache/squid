/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_ACTIONPARAMS_H
#define SQUID_SRC_MGR_ACTIONPARAMS_H

#include "anyp/Uri.h"
#include "http/RequestMethod.h"
#include "ipc/forward.h"
#include "mgr/QueryParams.h"
#include "RequestFlags.h"

namespace Mgr
{

/// Cache Manager Action parameters extracted from the user request
class ActionParams
{
public:
    ActionParams();

    explicit ActionParams(const Ipc::TypedMsgHdr &msg); ///< load from msg
    void pack(Ipc::TypedMsgHdr &msg) const; ///< store into msg

public:
    /* details of the client HTTP request that caused the action */
    HttpRequestMethod httpMethod; ///< HTTP request method
    AnyP::Uri httpUri; ///< HTTP request URI
    RequestFlags httpFlags; ///< HTTP request flags
    String httpOrigin;       ///< HTTP Origin: header (if any)

    /* action parameters extracted from the client HTTP request */
    SBuf actionName; ///< action name (and credentials realm)
    String userName; ///< user login name; currently only used for logging
    String password; ///< user password; used for acceptance check and cleared
    QueryParams queryParams;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_ACTIONPARAMS_H */

