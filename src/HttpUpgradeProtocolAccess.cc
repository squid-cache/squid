/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "globals.h"
#include "HttpUpgradeProtocolAccess.h"
#include "sbuf/Stream.h"

#include <algorithm>

const SBuf HttpUpgradeProtocolAccess::ProtoOther("OTHER");

ProtocolView::ProtocolView(const char * const start, const size_t len):
    ProtocolView(SBuf(start, len))
{
}

ProtocolView::ProtocolView(const SBuf &proto):
    name(proto.substr(0, proto.find('/'))),
    version(proto.substr(name.length()))
{
}

std::ostream &
operator <<(std::ostream &os, const ProtocolView &view)
{
    os << view.name;
    if (!view.version.isEmpty())
        os << view.version;
    return os;
}

/* HttpUpgradeProtocolAccess */

HttpUpgradeProtocolAccess::~HttpUpgradeProtocolAccess()
{
    aclDestroyAccessList(&other);
}

void
HttpUpgradeProtocolAccess::configureGuard(ConfigParser &parser)
{
    const auto rawProto = parser.NextToken();
    if (!rawProto)
        throw TextException(ToSBuf("expected a protocol name or ", ProtoOther), Here());

    if (ProtoOther.cmp(rawProto) == 0) {
        aclParseAccessLine(cfg_directive, parser, &other);
        return;
    }

    // To preserve ACL rules checking order, to exclude inapplicable (i.e. wrong
    // protocol version) rules, and to keep things simple, we merge no rules.
    acl_access *access = nullptr;
    aclParseAccessLine(cfg_directive, parser, &access);
    if (access)
        namedGuards.emplace_back(rawProto, access);
}

/* HttpUpgradeProtocolAccess::NamedGuard */

HttpUpgradeProtocolAccess::NamedGuard::NamedGuard(const char *rawProtocol, acl_access *acls):
    protocol(rawProtocol),
    proto(protocol),
    guard(acls)
{
}

HttpUpgradeProtocolAccess::NamedGuard::~NamedGuard() {
    aclDestroyAccessList(&guard);
}

