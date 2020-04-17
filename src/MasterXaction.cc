/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MasterXaction.h"

InstanceIdDefinitions(MasterXaction, "master", uint64_t);

MasterXaction::Pointer
MasterXaction::spawnChildLayer(const char *name) const
{
    // we are producing essentially a copy - but there are state differences
    txChild = new MasterXaction(initiator, name);

    // txChild->id - use newly generated on
    txChild->txParent = this;
    // txChild->xtChild - leave as nullptr
    txChild->squidPort = squidPort;
    // txChild->initiator - we do not (yet) distinguish initiator when nesting

    txChild->tcpClient = tcpClient;

    txChild->generatingConnect = generatingConnect;

    return txChild;
}

