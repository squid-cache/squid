/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "tunnel.cc"
#include "tests/STUB.h"

#include "FwdState.h"
class ClientHttpRequest;

void tunnelStart(ClientHttpRequest *) STUB

void switchToTunnel(HttpRequest *, const Comm::ConnectionPointer &, const Comm::ConnectionPointer &, const SBuf &) STUB

