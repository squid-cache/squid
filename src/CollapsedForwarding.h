/*
 * DEBUG: section 17    Request Forwarding
 *
 */

#ifndef SQUID_COLLAPSED_FORWARDING_H
#define SQUID_COLLAPSED_FORWARDING_H

#include "ipc/Queue.h"
#include "ipc/forward.h"

#include <memory>

class StoreIOState;

/// Sends and handles collapsed forwarding notifications.
class CollapsedForwarding
{
public:
    /// open shared memory segment
    static void Init();

    /// notify other workers that new data is available
    static void NewData(const StoreIOState &sio);

    /// kick worker with empty IPC queue
    static void Notify(const int workerId);

    /// handle new data messages in IPC queue
    static void HandleNewData(const char *const when);

    /// handle queue push notifications from worker or disker
    static void HandleNotification(const Ipc::TypedMsgHdr &msg);

private:
    typedef Ipc::MultiQueue Queue;
    static std::auto_ptr<Queue> queue; ///< IPC queue
};

#endif /* SQUID_COLLAPSED_FORWARDING_H */
