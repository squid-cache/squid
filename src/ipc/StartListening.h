/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_START_LISTENING_H
#define SQUID_IPC_START_LISTENING_H

#include "base/Subscription.h"
#include "comm/forward.h"
#include "ip/forward.h"
#include "ipc/FdNotes.h"
#include "base/AsyncCall.h"

#if HAVE_IOSFWD
#include <iosfwd>
#endif

namespace Ipc
{

/// common API for all StartListening() callbacks
class StartListeningCb
{
public:
    StartListeningCb();
    virtual ~StartListeningCb();

    /// starts printing arguments, return os
    std::ostream &startPrint(std::ostream &os) const;

public:
    Comm::ConnectionPointer conn; ///< opened listening socket
    int errNo; ///< errno value from the comm_open_listener() call
    Subscription::Pointer handlerSubscription; ///< The subscription we will pass on to the ConnAcceptor
};

/// Depending on whether SMP is on, either ask Coordinator to send us
/// the listening FD or open a listening socket directly.
void StartListening(int sock_type, int proto, const Comm::ConnectionPointer &listenConn,
                    FdNoteId fdNote, AsyncCall::Pointer &callback);

} // namespace Ipc;

#endif /* SQUID_IPC_START_LISTENING_H */
