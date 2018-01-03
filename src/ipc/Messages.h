/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

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
               mtCollapsedForwardingNotification,
               mtCacheMgrRequest, mtCacheMgrResponse
#if SQUID_SNMP
               ,
               mtSnmpRequest, mtSnmpResponse
#endif
             } MessageType;

} // namespace Ipc;

#endif /* SQUID_IPC_MESSAGES_H */

