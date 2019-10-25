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
#include "sbuf/Stream.h"

/// A protocol-comparing predicate for STL search algorithms.
/// Helps (and optimizes) checking whether the reference protocol belongs to an
/// STL container, where the reference protocol and container protocols may be
/// versioned. For example, it helps find "b/1" in ("a/1", "B").
/// This predicate intentionally does not find "a" in ("a/1", "a/2").
class MatchProtocol
{
public:
    MatchProtocol(const char *p, size_t len):
        reference(p),
        referenceLen(len)
    {
        const auto end = std::find(reference, reference + referenceLen, '/');
        referenceBaseLen = end - reference;
    }

    /// equality check for searching in sequence containers like std::list
    bool operator() (const SBuf &item) const
    {
        // optimization: one of the lengths must match regardless of versioning
        if (item.length() != referenceLen && item.length() != referenceBaseLen)
            return false;

        auto cmpLen = referenceLen;
        if (referenceIsVersioned()) {
            const auto itemIsVersioned = (item.find('/') != SBuf::npos);
            if (!itemIsVersioned)
                cmpLen = referenceBaseLen;
        }
        return item.length() == cmpLen && item.caseCmp(reference, cmpLen) == 0;
    }

    /// equality check for searching in associative containers like std::map
    template<typename T>
    bool operator() (const std::pair<const SBuf, T> &itemPair) const
    {
        return (*this)(itemPair.first);
    }

private:
    /// \returns whether the reference protocol includes version info
    bool referenceIsVersioned() const { return (referenceBaseLen != referenceLen); }

    /// the protocol name[/version] that our user is looking for
    const char *reference;

    /// reference protocol length, including the /version part
    size_t referenceLen;

    /// reference protocol length, excluding the /version part
    size_t referenceBaseLen;
};

const SBuf HttpUpgradeProtocolAccess::ProtoOther("OTHER");

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

acl_access*
HttpUpgradeProtocolAccess::findGuard(const char *name, const size_t len) const
{
    const MatchProtocol match(name, len);
    for (auto &namedGuard: namedGuards) {
        if (match(namedGuard.first))
            return namedGuard.second;
    }

    // if no rules mention the protocol explicitly, try OTHER protocol rules
    return other; // may be nil
}

