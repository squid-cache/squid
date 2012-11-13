/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_MESSAGES_H
#define SQUID_IPC_MESSAGES_H

/** Declarations used by various IPC messages */

namespace Ipc
{

/// message class identifier
typedef enum { mtNone = 0, mtRegistration,
               mtStrandSearchRequest, mtStrandSearchResponse,
               mtSharedListenRequest, mtSharedListenResponse,
               mtIpcIoNotification,
               mtCacheMgrRequest, mtCacheMgrResponse
#if SQUID_SNMP
               ,
               mtSnmpRequest, mtSnmpResponse
#endif
             } MessageType;

} // namespace Ipc;

#endif /* SQUID_IPC_MESSAGES_H */
