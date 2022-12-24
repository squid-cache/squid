/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_FORWARDER_H
#define SQUID_IPC_FORWARDER_H

#include "base/AsyncJob.h"
#include "base/forward.h"
#include "cbdata.h"
#include "ipc/Request.h"
#include "mgr/ActionParams.h"

#include <map>

namespace Ipc
{

/** Forwards a worker request to coordinator.
 * Waits for an ACK from Coordinator
 * Send the data unit with an error response if forwarding fails.
 */
class Forwarder: public AsyncJob
{
    CBDATA_CLASS(Forwarder);

public:
    Forwarder(Request::Pointer aRequest, double aTimeout);
    virtual ~Forwarder();

    /// finds and calls the right Forwarder upon Coordinator's response
    static void HandleRemoteAck(RequestId);

    /* has-to-be-public AsyncJob API */
    virtual void callException(const std::exception& e);

    CodeContextPointer codeContext;

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;

    virtual void handleError();
    virtual void handleTimeout();
    virtual void handleException(const std::exception& e);

private:
    static void RequestTimedOut(void* param);
    void requestTimedOut();
    void removeTimeoutEvent();

    void handleRemoteAck();

    static AsyncCall::Pointer DequeueRequest(RequestId::Index);

protected:
    Request::Pointer request;
    const double timeout; ///< response wait timeout in seconds

    /// maps request->id to Forwarder::handleRemoteAck callback
    typedef std::map<RequestId::Index, AsyncCall::Pointer> RequestsMap;
    static RequestsMap TheRequestsMap; ///< pending Coordinator requests

    static RequestId::Index LastRequestId; ///< last requestId used
};

} // namespace Ipc

#endif /* SQUID_IPC_FORWARDER_H */

