/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_STRAND_H
#define SQUID_IPC_STRAND_H

#include "ipc/forward.h"
#include "ipc/Port.h"
#include "mgr/forward.h"
#if SQUID_SNMP
#include "snmp/forward.h"
#endif

namespace Ipc
{

class StrandCoord;

/// Receives coordination messages on behalf of its process or thread
class Strand: public Port
{
    CBDATA_CHILD(Strand);

public:
    Strand();

    void start() override; // Port (AsyncJob) API

protected:
    void timedout() override; // Port (UsdOp) API
    void receive(const TypedMsgHdr &message) override; // Port API

private:
    void registerSelf(); /// let Coordinator know this strand exists
    void handleRegistrationResponse(const StrandMessage &);
    void handleCacheMgrRequest(const Mgr::Request& request);
    void handleCacheMgrResponse(const Mgr::Response& response);
#if SQUID_SNMP
    void handleSnmpRequest(const Snmp::Request& request);
    void handleSnmpResponse(const Snmp::Response& response);
#endif

private:
    bool isRegistered; ///< whether Coordinator ACKed registration (unused)

private:
    Strand(const Strand&); // not implemented
    Strand& operator =(const Strand&); // not implemented
};

}

#endif /* SQUID_IPC_STRAND_H */

