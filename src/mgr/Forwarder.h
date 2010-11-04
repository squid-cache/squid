/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_FORWARDER_H
#define SQUID_MGR_FORWARDER_H

#include "base/AsyncJob.h"
#include "mgr/ActionParams.h"
#include <map>


class CommCloseCbParams;
class HttpRequest;
class StoreEntry;
class ErrorState;

namespace Mgr
{

/** Forwards a single client cache manager request to Coordinator.
 * Waits for an ACK from Coordinator while holding the Store entry.
 * Fills the store entry with an error response if forwarding fails.
 */
class Forwarder: public AsyncJob
{
public:
    Forwarder(int aFd, const ActionParams &aParams, HttpRequest* aRequest,
              StoreEntry* anEntry);
    virtual ~Forwarder();

    /// finds and calls the right Forwarder upon Coordinator's response
    static void HandleRemoteAck(unsigned int requestId);

    /* has-to-be-public AsyncJob API */
    virtual void callException(const std::exception& e);

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;

private:
    void handleRemoteAck();
    static void RequestTimedOut(void* param);
    void requestTimedOut();
    void quitOnError(const char *reason, ErrorState *error);
    void noteCommClosed(const CommCloseCbParams& params);
    void removeTimeoutEvent();
    static AsyncCall::Pointer DequeueRequest(unsigned int requestId);
    static void Abort(void* param);
    void close();

private:
    ActionParams params; ///< action parameters to pass to the other side
    HttpRequest* request; ///< HTTP client request for detailing errors
    StoreEntry* entry; ///< Store entry expecting the response
    int fd; ///< HTTP client connection descriptor
    unsigned int requestId; ///< request id
    AsyncCall::Pointer closer; ///< comm_close handler for the HTTP connection

    /// maps requestId to Forwarder::handleRemoteAck callback
    typedef std::map<unsigned int, AsyncCall::Pointer> RequestsMap;
    static RequestsMap TheRequestsMap; ///< pending Coordinator requests

    static unsigned int LastRequestId; ///< last requestId used

    CBDATA_CLASS2(Forwarder);
};

} // namespace Mgr

#endif /* SQUID_MGR_FORWARDER_H */
