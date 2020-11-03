/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "CachePeer.cc"
#include "tests/STUB.h"

#include "CachePeer.h"

time_t CachePeer::connectTimeout() const STUB_RETVAL(0)
