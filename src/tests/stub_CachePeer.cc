/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "CachePeer.cc"
#include "tests/STUB.h"

#include "CachePeer.h"
void CachePeer::rename(const char *) STUB
time_t CachePeer::connectTimeout() const STUB_RETVAL(0)
std::ostream &operator <<(std::ostream &os, const CachePeer &) STUB_RETVAL(os)

