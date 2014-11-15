/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "security/libsecurity.la"
#include "tests/STUB.h"

#include "security/PeerOptions.h"
Security::PeerOptions Security::SslProxyConfig;
void Security::PeerOptions::parse(char const*) STUB
Security::ContextPointer Security::PeerOptions::createContext() STUB_RETVAL(NULL)
