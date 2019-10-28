/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "globals.h"
#include "HttpUpgrade.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

#include <algorithm>

const SBuf HttpUpgradeProtocolAccess::ProtoOther("OTHER");

ProtocolView::ProtocolView(const char * const start, const size_t len):
    name(start, std::find(start, start + len, '/') - start),
    version(start + name.size(), len - name.size())
{
}

ProtocolView::ProtocolView(const SBuf &proto):
    ProtocolView(proto.rawContent(), proto.length())
{
}

ProtocolView::ProtocolView(const StringView &proto):
    ProtocolView(proto.data(), proto.size())
{
}

std::ostream &
operator <<(std::ostream &os, const ProtocolView &view)
{
    os << view.name;
    if (!view.version.empty())
        os << view.version;
    return os;
}

/* HttpUpgradeProtocolAccess */

HttpUpgradeProtocolAccess::~HttpUpgradeProtocolAccess()
{
    for (const auto &namedGuard: namedGuards) {
        auto acls = namedGuard.second;
        aclDestroyAccessList(&acls);
    }
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

    const SBuf proto(rawProto);

    const auto namedGuard = namedGuards.find(proto);
    if (namedGuard != namedGuards.end()) {
        assert(namedGuard->second);
        aclParseAccessLine(cfg_directive, parser, &namedGuard->second);
        return;
    }

    acl_access *access = nullptr;
    aclParseAccessLine(cfg_directive, parser, &access);
    if (access)
        namedGuards.emplace(proto, access);
}

const acl_access*
HttpUpgradeProtocolAccess::findGuard(const StringView &proto) const
{
    const ProtocolView needle(proto.data(), proto.size());
    for (auto &namedGuard: namedGuards) {
        if (AinB(needle, ProtocolView(namedGuard.first)))
            return namedGuard.second;
    }

    // if no rules mention the protocol explicitly, try OTHER protocol rules
    return other; // may be nil
}

