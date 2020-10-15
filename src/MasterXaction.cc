/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MasterXaction.h"
#include "sbuf/Stream.h"

InstanceIdDefinitions(MxId, "mx", uint64_t);
const MxId::Pointer MxId::Nil;
InstanceIdDefinitions(MasterXaction, "tx", uint64_t);

const SBuf
MasterXaction::printId() const
{
    SBufStream out;
    if (txParent)
        out << txParent << "::";
    else
        out << xid << "::";
    out << pxid;
    return out.buf();
}

MasterXaction::Pointer
MasterXaction::spawnChildLayer(const char *name) const
{
    // we are producing essentially a copy - but there are state differences
    txChild = new MasterXaction(initiator, name, xid);

    // txChild->xid - leave as constructed
    // txChild->pxid - leave as constructed
    txChild->txParent = this;
    // txChild->xtChild - leave as nullptr
    txChild->squidPort = squidPort;
    // txChild->initiator - we do not (yet) distinguish initiator when nesting

    txChild->tcpClient = tcpClient;

    txChild->generatingConnect = generatingConnect;

    return txChild;
}

