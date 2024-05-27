/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ConfigParser.h"

#define STUB_API "HttpUpgradeProtocolAccess.cc"
#include "tests/STUB.h"

#include "HttpUpgradeProtocolAccess.h"
ProtocolView::ProtocolView(const char * const, const size_t) STUB
ProtocolView::ProtocolView(SBuf const &) STUB
std::ostream &operator <<(std::ostream &os, const ProtocolView &) STUB_RETVAL(os)
HttpUpgradeProtocolAccess::~HttpUpgradeProtocolAccess() STUB
void HttpUpgradeProtocolAccess::configureGuard(ConfigParser &) STUB
HttpUpgradeProtocolAccess::NamedGuard::~NamedGuard() STUB_NOP
HttpUpgradeProtocolAccess::NamedGuard::NamedGuard(const char *, const acl_access &): protocol("STUB-UNDEF"), proto(protocol) STUB_NOP

