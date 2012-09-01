/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_FILLER_H
#define SQUID_MGR_FILLER_H

#include "comm/forward.h"
#include "HttpRequestMethod.h"
#include "mgr/Action.h"
#include "mgr/StoreToCommWriter.h"

namespace Mgr
{

/// provides Coordinator with a local cache manager response
class Filler: public StoreToCommWriter
{
public:
    Filler(const Action::Pointer &anAction, const Comm::ConnectionPointer &conn, unsigned int aRequestId);

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();

private:
    Action::Pointer action; ///< action that will run() and sendResponse()
    unsigned int requestId; ///< the ID of the Request we are responding to

    CBDATA_CLASS2(Filler);
};

} // namespace Mgr

#endif /* SQUID_MGR_FILLER_H */
