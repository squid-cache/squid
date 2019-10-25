/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_UPGRADE_H
#define SQUID_HTTP_UPGRADE_H

#include "acl/forward.h"
#include "acl/forward.h"

#include <map>

/// Allows or blocks HTTP Upgrade protocols (see http_upgrade_request_protocols)
class HttpUpgradeProtocolAccess
{
public:
    HttpUpgradeProtocolAccess() {}
    ~HttpUpgradeProtocolAccess();
    HttpUpgradeProtocolAccess(HttpUpgradeProtocolAccess &&) = delete; // no copying of any kind

    /// \returns the ACL list matching the named protocol (or nil)
    /// \param proto versioned or versionless protocol name; not 0-terminated!
    /// \param len proto length; includes the /version part, if any
    acl_access *findGuard(const char *proto, const size_t len) const;

    /// parses a single allow/deny rule
    void configureGuard(ConfigParser&);

    /// iterate over all rules; TODO: We should add a general Dumper API instead
    template <typename Visitor>
    void forEachRule(const Visitor &visitor) const
    {
        for (const auto &namedGuard: namedGuards)
            visitor(namedGuard.first, namedGuard.second);
        visitor(ProtoOther, other);
    }

private:
    /// pseudonym to specify rules for "all other protocols"
    static const SBuf ProtoOther;

    /// maps HTTP Upgrade protocol name/version to the ACLs guarding its usage
    typedef std::map<SBuf, acl_access*> NamedProtocolAccess;

    /// rules governing upgrades to explicitly named protocols
    NamedProtocolAccess namedGuards;

    /// OTHER rules governing unnamed protocols
    acl_access *other = nullptr;
};

#endif /* SQUID_HTTP_UPGRADE_H */

