/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_MESSAGES_H
#define SQUID_IPC_MESSAGES_H

#include "ipc/forward.h"
#include <sys/types.h>

/** Declarations used by varios IPC messages */

namespace Ipc
{

/// message class identifier
typedef enum { mtNone = 0, mtRegistration,
               mtSharedListenRequest, mtSharedListenResponse,
               mtCacheMgrRequest, mtCacheMgrResponse
             } MessageType;

} // namespace Ipc;


#endif /* SQUID_IPC_MESSAGES_H */
