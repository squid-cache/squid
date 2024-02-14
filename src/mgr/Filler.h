/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_FILLER_H
#define SQUID_SRC_MGR_FILLER_H

#include "comm/forward.h"
#include "ipc/forward.h"
#include "mgr/Action.h"
#include "mgr/StoreToCommWriter.h"

namespace Mgr
{

/// provides Coordinator with a local cache manager response
class Filler: public StoreToCommWriter
{
    CBDATA_CHILD(Filler);

public:
    Filler(const Action::Pointer &, const Comm::ConnectionPointer &, Ipc::RequestId);

protected:
    /* AsyncJob API */
    void start() override;
    void swanSong() override;

private:
    Action::Pointer action; ///< action that will run() and sendResponse()
    Ipc::RequestId requestId; ///< the ID of the Request we are responding to
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_FILLER_H */

