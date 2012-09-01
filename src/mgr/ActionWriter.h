/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_ACTION_WRITER_H
#define SQUID_MGR_ACTION_WRITER_H

#include "comm/forward.h"
#include "HttpRequestMethod.h"
#include "mgr/StoreToCommWriter.h"

namespace Mgr
{

/// Creates Store entry, fills it using action's fillEntry(), and
/// Comm-writes it using parent StoreToCommWriter.
class ActionWriter: public StoreToCommWriter
{
public:
    ActionWriter(const Action::Pointer &anAction, const Comm::ConnectionPointer &conn);

protected:
    /* AsyncJob API */
    virtual void start();

private:
    Action::Pointer action; ///< action that fills the entry

    CBDATA_CLASS2(ActionWriter);
};

} // namespace Mgr

#endif /* SQUID_MGR_ACTION_WRITER_H */
