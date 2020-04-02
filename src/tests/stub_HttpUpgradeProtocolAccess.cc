/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "HttpUpgradeProtocolAccess.cc"
#include "STUB.h"

#include "ConfigParser.h"
#include "HttpUpgradeProtocolAccess.h"

const SBuf HttpUpgradeProtocolAccess::ProtoOther("STUB-OTHER");

HttpUpgradeProtocolAccess::~HttpUpgradeProtocolAccess() STUB
void HttpUpgradeProtocolAccess::configureGuard(ConfigParser &) STUB
ProtocolView::ProtocolView(StringView const&) STUB

std::ostream &operator <<(std::ostream &os, const ProtocolView &view)
{
    STUB;
    return os;
}
