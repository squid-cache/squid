/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_FORWARDER_H
#define SQUID_MGR_FORWARDER_H

#include "comm/forward.h"
#include "ipc/Forwarder.h"
#include "mgr/ActionParams.h"

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
class Forwarder: public Ipc::Forwarder
{
public:
    Forwarder(const Comm::ConnectionPointer &aConn, const ActionParams &aParams, HttpRequest* aRequest,
              StoreEntry* anEntry);
    virtual ~Forwarder();

protected:
    /* Ipc::Forwarder API */
    virtual void cleanup(); ///< perform cleanup actions
    virtual void handleError();
    virtual void handleTimeout();
    virtual void handleException(const std::exception& e);
    virtual void handleRemoteAck();

private:
    void noteCommClosed(const CommCloseCbParams& params);
    void sendError(ErrorState* error);

private:
    HttpRequest* httpRequest; ///< HTTP client request for detailing errors
    StoreEntry* entry; ///< Store entry expecting the response
    Comm::ConnectionPointer conn; ///< HTTP client connection descriptor
    AsyncCall::Pointer closer; ///< comm_close handler for the HTTP connection

    CBDATA_CLASS2(Forwarder);
};

} // namespace Mgr

#endif /* SQUID_MGR_FORWARDER_H */
