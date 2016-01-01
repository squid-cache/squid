/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#ifndef SQUID_SNMPX_FORWARDER_H
#define SQUID_SNMPX_FORWARDER_H

#include "ipc/Forwarder.h"
#include "snmp/Pdu.h"
#include "snmp/Session.h"

class CommCloseCbParams;

namespace Snmp
{

/** Forwards a single client SNMP request to Coordinator.
 * Waits for an ACK from Coordinator
 * Send the data unit with an error response if forwarding fails.
 */
class Forwarder: public Ipc::Forwarder
{
public:
    Forwarder(const Pdu& aPdu, const Session& aSession, int aFd,
              const Ip::Address& anAddress);

protected:
    /* Ipc::Forwarder API */
    virtual void cleanup(); ///< perform cleanup actions
    virtual void handleTimeout();
    virtual void handleException(const std::exception& e);

private:
    void noteCommClosed(const CommCloseCbParams& params);
    void sendError(int error);

private:
    int fd; ///< client connection descriptor
    AsyncCall::Pointer closer; ///< comm_close handler for the connection

    CBDATA_CLASS2(Forwarder);
};

void SendResponse(unsigned int requestId, const Pdu& pdu);

} // namespace Snmp

#endif /* SQUID_SNMPX_FORWARDER_H */

