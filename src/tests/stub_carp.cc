/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "carp.cc"
#include "tests/STUB.h"

class CachePeer;
class PeerSelector;

void carpInit(void) STUB
CachePeer *carpSelectParent(PeerSelector *ps) STUB_RETVAL(nullptr)

