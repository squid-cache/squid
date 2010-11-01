/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_REQUEST_H
#define SQUID_MGR_REQUEST_H

#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionParams.h"


namespace Mgr
{

/// cache manager request
class Request
{
public:
    Request(int aRequestorId, unsigned int aRequestId, int aFd,
            const ActionParams &aParams);

    explicit Request(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()

public:
    int requestorId; ///< kidId of the requestor; used for response destination
    unsigned int requestId; ///< unique for sender; matches request w/ response
    int fd; ///< HTTP client connection descriptor

    ActionParams params; ///< action name and parameters
};


} // namespace Mgr

#endif /* SQUID_MGR_REQUEST_H */
