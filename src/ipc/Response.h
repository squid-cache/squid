/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_RESPONSE_H
#define SQUID_IPC_RESPONSE_H

#include "base/RefCount.h"
#include "ipc/forward.h"

namespace Ipc
{

/// A response to Ipc::Request.
class Response: public RefCountable
{
public:
    typedef RefCount<Response> Pointer;

public:
    explicit Response(unsigned int aRequestId):
            requestId(aRequestId) {}

    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

private:
    Response(const Response&); // not implemented
    Response& operator= (const Response&); // not implemented

public:
    unsigned int requestId; ///< ID of request we are responding to
};

inline
std::ostream& operator << (std::ostream &os, const Response& response)
{
    os << "[response.requestId %u]" << response.requestId << '}';
    return os;
}

} // namespace Ipc

#endif /* SQUID_IPC_RESPONSE_H */
