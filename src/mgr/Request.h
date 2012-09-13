/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_REQUEST_H
#define SQUID_MGR_REQUEST_H

#include "ipc/forward.h"
#include "ipc/Request.h"
#include "mgr/ActionParams.h"

namespace Mgr
{

/// cache manager request
class Request: public Ipc::Request
{
public:
    Request(int aRequestorId, unsigned int aRequestId, const Comm::ConnectionPointer &aConn,
            const ActionParams &aParams);

    explicit Request(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    /* Ipc::Request API */
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual Pointer clone() const;

private:
    Request(const Request& request);

public:
    Comm::ConnectionPointer conn; ///< HTTP client connection descriptor

    ActionParams params; ///< action name and parameters
};

} // namespace Mgr

#endif /* SQUID_MGR_REQUEST_H */
