/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_SRC_IPC_STARTLISTENING_H
#define SQUID_SRC_IPC_STARTLISTENING_H

#include "base/AsyncCall.h"
#include "base/forward.h"
#include "base/Subscription.h"
#include "comm/forward.h"
#include "ip/forward.h"
#include "ipc/FdNotes.h"

#include <iosfwd>

namespace Ipc
{

/// StartListening() result
class StartListeningAnswer
{
public:
    Comm::ConnectionPointer conn; ///< opened listening socket
    int errNo = 0; ///< errno value from the comm_open_listener() call
};

using StartListeningCallback = AsyncCallback<StartListeningAnswer>;

/// Depending on whether SMP is on, either ask Coordinator to send us
/// the listening FD or open a listening socket directly.
void StartListening(int sock_type, int proto, const Comm::ConnectionPointer &listenConn,
                    FdNoteId, StartListeningCallback &);

std::ostream &operator <<(std::ostream &, const StartListeningAnswer &);

} // namespace Ipc;

#endif /* SQUID_SRC_IPC_STARTLISTENING_H */

