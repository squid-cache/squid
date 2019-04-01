/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMM_UDPOPENDIALER_H
#define SQUID_COMM_UDPOPENDIALER_H

#include "ipc/StartListening.h"

namespace Comm
{

/// dials a UDP port-opened call
class UdpOpenDialer: public CallDialer,
    public Ipc::StartListeningCb
{
public:
    typedef void (*Handler)(const Comm::ConnectionPointer &conn, int errNo);
    UdpOpenDialer(Handler aHandler): handler(aHandler) {}

    virtual void print(std::ostream &os) const { startPrint(os) << ')'; }
    virtual bool canDial(AsyncCall &) const { return true; }
    virtual void dial(AsyncCall &) { (handler)(conn, errNo); }

public:
    Handler handler;
};

} // namespace Comm

#endif /* SQUID_COMM_UDPOPENDIALER_H */

