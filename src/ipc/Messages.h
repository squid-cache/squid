/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
typedef enum { enumBegin_ = 0,
               mtRegistration, ///< strand registration with Coordinator (also used as an ACK)
               mtForegroundRebuild, ///< the disker is building its index in foreground mode
               mtRebuildFinished, ///< the disker rebuilt its index
               mtFindStrand, ///< a worker requests a strand from Coordinator
               /// a mtFindStrand answer: the strand exists but needs more time to become usable
               /// the sender should send mtStrandReady (or more mtStrandBusy) later
               mtStrandBusy,
               mtStrandReady, ///< a mtFindStrand answer: the strand exists and should be usable
               mtSharedListenRequest,
               mtSharedListenResponse,
               mtIpcIoNotification,
               mtCollapsedForwardingNotification,
               mtCacheMgrRequest,
               mtCacheMgrResponse
#if SQUID_SNMP
               ,
               mtSnmpRequest,
               mtSnmpResponse
#endif
               ,
               enumEnd_
             } MessageType;

} // namespace Ipc;

#endif /* SQUID_IPC_MESSAGES_H */

