/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef TUNNEL_H_
#define TUNNEL_H_

#include "comm/forward.h"
#include "sbuf/forward.h"

class HttpRequest;
void switchToTunnel(HttpRequest *request, const Comm::ConnectionPointer &clientConn, const Comm::ConnectionPointer &srvConn, const SBuf &preReadServerData);

#endif /* TUNNEL_H_ */

