/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_INQUIRER_H
#define SQUID_MGR_INQUIRER_H

#include "comm/forward.h"
#include "ipc/Inquirer.h"
#include "mgr/Action.h"

class CommIoCbParams;
class CommCloseCbParams;

namespace Mgr
{

/// Coordinator's job that sends a cache manage request to each strand,
/// aggregating individual strand responses and dumping the result if needed
class Inquirer: public Ipc::Inquirer
{
    CBDATA_CLASS(Inquirer);

public:
    Inquirer(Action::Pointer anAction, const Request &aCause,
             const Ipc::StrandCoords &coords);

protected:
    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const;

    /* Ipc::Inquirer API */
    virtual void cleanup();
    virtual void sendResponse();
    virtual bool aggregate(Ipc::Response::Pointer aResponse);

private:
    void noteWroteHeader(const CommIoCbParams& params);
    void noteCommClosed(const CommCloseCbParams& params);
    void removeCloseHandler();
    Ipc::StrandCoords applyQueryParams(const Ipc::StrandCoords& aStrands,
                                       const QueryParams& aParams);
private:
    Action::Pointer aggrAction; //< action to aggregate

    Comm::ConnectionPointer conn; ///< HTTP client socket descriptor

    AsyncCall::Pointer writer; ///< comm_write callback
    AsyncCall::Pointer closer; ///< comm_close handler
};

} // namespace Mgr

#endif /* SQUID_MGR_INQUIRER_H */

