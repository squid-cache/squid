/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_RESPONSE_H
#define SQUID_MGR_RESPONSE_H

#include "mgr/Action.h"


namespace Mgr
{

/// A response to Mgr::Request.
/// May carry strand action data to be aggregated with data from other strands.
class Response
{
public:
    Response(unsigned int aRequestId = 0, Action::Pointer anAction = NULL);

    explicit Response(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()
    bool hasAction() const; ///< whether response contain action object
    const Action& getAction() const; ///< returns action object

public:
    unsigned int requestId; ///< ID of request we are responding to
    Action::Pointer action; ///< action relating to response
};

extern std::ostream& operator <<(std::ostream &os, const Response &response);

} // namespace Mgr

#endif /* SQUID_MGR_RESPONSE_H */
