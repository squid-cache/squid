/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "security/libsecurity.la"
#include "tests/STUB.h"

#include "security/PeerOptions.h"
Security::PeerOptions Security::ProxyOutgoingConfig;
void Security::PeerOptions::parse(char const*) STUB
Security::ContextPointer Security::PeerOptions::createContext(bool) STUB_RETVAL(NULL)
void parse_securePeerOptions(Security::PeerOptions *) STUB

