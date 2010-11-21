/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_START_LISTENING_H
#define SQUID_IPC_START_LISTENING_H

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
    int fd; ///< opened listening socket or -1
    int errNo; ///< errno value from the comm_open_listener() call
};

/// Depending on whether SMP is on, either ask Coordinator to send us
/// the listening FD or call comm_open_listener() directly.
extern void StartListening(int sock_type, int proto, Ip::Address &addr,
                           int flags, FdNoteId fdNote, AsyncCall::Pointer &callback);

} // namespace Ipc;


#endif /* SQUID_IPC_START_LISTENING_H */
