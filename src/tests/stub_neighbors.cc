/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "neighbors.cc"
#include "tests/STUB.h"

#include "FwdState.h"
#include "neighbors.h"

void
peerConnClosed(CachePeer *p) STUB

time_t
peerConnectTimeout(const CachePeer *peer) STUB_RETVAL(0)
time_t
FwdState::ForwardTimeout(const time_t) STUB_RETVAL(0)
bool
FwdState::EnoughTimeToReForward(const time_t fwdStart) STUB_RETVAL(false)

