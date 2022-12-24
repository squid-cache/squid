/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
const acl_access *HttpUpgradeProtocolAccess::findGuard(const SBuf &) const STUB_RETVAL(nullptr)
void HttpUpgradeProtocolAccess::configureGuard(ConfigParser &) STUB
const SBuf HttpUpgradeProtocolAccess::ProtoOther("STUB-OTHER");
HttpUpgradeProtocolAccess::NamedGuard::~NamedGuard() STUB_NOP
HttpUpgradeProtocolAccess::NamedGuard::NamedGuard(const char *, acl_access *): protocol("STUB-UNDEF"), proto(protocol) STUB_NOP

