/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "HierarchyLogEntry.h"

#define STUB_API "access.log.cc"
#include "tests/STUB.h"

HierarchyLogEntry::HierarchyLogEntry() STUB

void HierarchyLogEntry::notePeerRead() STUB
void HierarchyLogEntry::notePeerWrite() STUB
bool HierarchyLogEntry::peerResponseTime(struct timeval &) STUB_RETVAL(false)
bool HierarchyLogEntry::totalResponseTime(struct timeval &) STUB_RETVAL(false)

ping_data::ping_data() :
    n_sent(0),
    n_recv(0),
    n_replies_expected(0),
    timeout(0),
    timedout(0),
    w_rtt(0),
    p_rtt(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}

