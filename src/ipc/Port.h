/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_PORT_H
#define SQUID_IPC_PORT_H

#include "ipc/UdsOp.h"
#include "SquidString.h"

namespace Ipc
{

/// Waits for and receives incoming IPC messages; kids handle the messages
class Port: public UdsOp
{
public:
    Port(const String &aListenAddr);
    /// calculates IPC message address for strand #id of processLabel type
    static String MakeAddr(const char *proccessLabel, int id);

    /// get the IPC message address for coordinator process
    static String CoordinatorAddr();

protected:
    virtual void start() = 0; // UdsOp (AsyncJob) API; has body
    virtual bool doneAll() const; // UdsOp (AsyncJob) API

    /// read the next incoming message
    void doListen();

    /// handle IPC message just read
    virtual void receive(const TypedMsgHdr& message) = 0;

private:
    void noteRead(const CommIoCbParams &params); // Comm callback API

private:
    TypedMsgHdr buf; ///< msghdr struct filled by Comm
};

extern const char strandAddrLabel[]; ///< strand's listening address unique label

} // namespace Ipc

#endif /* SQUID_IPC_PORT_H */

