/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_INQUIRER_H
#define SQUID_IPC_INQUIRER_H

#include "base/AsyncJob.h"
#include "base/AsyncJobCalls.h"
#include "base/forward.h"
#include "ipc/forward.h"
#include "ipc/Request.h"
#include "ipc/Response.h"
#include "ipc/StrandCoords.h"
#include <map>

namespace Ipc
{

/// Coordinator's job that sends a cache manage request to each strand,
/// aggregating individual strand responses and dumping the result if needed
class Inquirer: public AsyncJob
{
    CBDATA_CLASS(Inquirer);

public:
    Inquirer(Request::Pointer aRequest, const Ipc::StrandCoords& coords, double aTimeout);
    virtual ~Inquirer();

    /// finds and calls the right Inquirer upon strand's response
    static void HandleRemoteAck(const Response& response);

    /* has-to-be-public AsyncJob API */
    virtual void callException(const std::exception& e);

    CodeContextPointer codeContext;

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;
    virtual const char *status() const;

    /// inquire the next strand
    virtual void inquire();
    /// perform cleanup actions on completion of job
    virtual void cleanup();
    /// do specific exception handling
    virtual void handleException(const std::exception& e);
    /// send response to client
    virtual void sendResponse() = 0;
    /// perform aggregating of responses and returns true if need to continue
    virtual bool aggregate(Response::Pointer aResponse) = 0;

private:
    typedef UnaryMemFunT<Inquirer, Response::Pointer, Response::Pointer> HandleAckDialer;

    void handleRemoteAck(Response::Pointer response);

    static AsyncCall::Pointer DequeueRequest(RequestId::Index);

    static void RequestTimedOut(void* param);
    void requestTimedOut();
    void removeTimeoutEvent();

protected:
    Request::Pointer request; ///< cache manager request received from client

    Ipc::StrandCoords strands; ///< all strands we want to query, in order
    Ipc::StrandCoords::const_iterator pos; ///< strand we should query now

    const double timeout; ///< number of seconds to wait for strand response

    /// maps request->id to Inquirer::handleRemoteAck callback
    typedef std::map<RequestId::Index, AsyncCall::Pointer> RequestsMap;
    static RequestsMap TheRequestsMap; ///< pending strand requests

    static RequestId::Index LastRequestId; ///< last requestId used
};

} // namespace Ipc

#endif /* SQUID_IPC_INQUIRER_H */

