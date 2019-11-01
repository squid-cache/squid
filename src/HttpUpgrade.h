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
#include "base/StringView.h"
#include "sbuf/forward.h"

#include <map>

/// a reference to a protocol name[/version] string; no 0-termination is assumed
class ProtocolView
{
public:
    ProtocolView(const char * const start, const size_t len);
    explicit ProtocolView(const StringView &proto);
    explicit ProtocolView(const SBuf &proto);

    StringView name; ///< everything up to (but excluding) the first slash('/')
    StringView version; ///< everything after the name, including the slash('/')
};

std::ostream &operator <<(std::ostream &, const ProtocolView &);

// HTTP is not explicit about case sensitivity of Upgrade protocol strings, but
// there are bug reports showing different case variants used for WebSocket so
// we preserve the received case but compare case-insensitively.

/// Both have the same name and
/// either both have the same version or some have no version restrictions.
/// For example, "ws" is similar to "ws/1" while "ws/1" is similar to "ws".
inline bool
Similar(const ProtocolView &a, const ProtocolView &b)
{
    if (!SameButCase(a.name, b.name))
        return false;
    return a.version.empty() || b.version.empty() || a.version == b.version;
}

/// Either b has no version restrictions or both have the same version.
/// For example, "ws/1" is in "ws" but "ws" is not in "ws/1".
inline bool
vAinB(const ProtocolView &a, const ProtocolView &b)
{
    // Optimization: Do not assert(SameButCase(a.name, b.name)).
    return b.version.empty() || a.version == b.version;
}

/// Allows or blocks HTTP Upgrade protocols (see http_upgrade_request_protocols)
class HttpUpgradeProtocolAccess
{
public:
    HttpUpgradeProtocolAccess() {}
    ~HttpUpgradeProtocolAccess();
    HttpUpgradeProtocolAccess(HttpUpgradeProtocolAccess &&) = delete; // no copying of any kind

    /// \returns the ACLs matching the given "name[/version]" protocol (or nil)
    const acl_access *findGuard(const StringView &proto) const;

    /// parses a single allow/deny rule
    void configureGuard(ConfigParser&);

    /// iterates over all configured rules, calling the given visitor
    template <typename Visitor> inline void forEach(const Visitor &) const;

    /// iterates over rules applicable to the given protocol, calling visitor;
    /// breaks iteration if the visitor returns true
    template <typename Visitor> inline void forApplicable(const ProtocolView &, const Visitor &) const;

private:
    /// a single configured access rule for an explicitly named protocol
    class NamedGuard
    {
    public:
        NamedGuard(const char *rawProtocol, acl_access*);
        NamedGuard(const NamedGuard &&) = delete; // no copying of any kind
        ~NamedGuard();

        SBuf protocol; ///< configured protocol name (and version)
        ProtocolView proto; ///< optimization: compiled this->protocol info
        acl_access *guard = nullptr; ///< configured access rule; never nil
    };

    /// maps HTTP Upgrade protocol name/version to the ACLs guarding its usage
    typedef std::deque<NamedGuard> NamedGuards;

    /// pseudonym to specify rules for "all other protocols"
    static const SBuf ProtoOther;

    /// rules governing upgrades to explicitly named protocols
    NamedGuards namedGuards;

    /// OTHER rules governing unnamed protocols
    acl_access *other = nullptr;
};

template <typename Visitor>
inline void
HttpUpgradeProtocolAccess::forEach(const Visitor &visitor) const
{
    for (const auto &namedGuard: namedGuards)
        visitor(namedGuard.protocol, namedGuard.guard);
    if (other)
        visitor(ProtoOther, other);
}

template <typename Visitor>
inline void
HttpUpgradeProtocolAccess::forApplicable(const ProtocolView &offer, const Visitor &visitor) const
{
    auto seenApplicable = false;
    for (const auto &namedGuard: namedGuards) {
        if (!SameButCase(offer.name, namedGuard.proto.name))
            continue;
        if (vAinB(offer, namedGuard.proto) && visitor(namedGuard.protocol, namedGuard.guard))
            return;
        seenApplicable = true; // may already be true
    }
    if (!seenApplicable && other) // OTHER is applicable if named rules were not
        (void)visitor(ProtoOther, other);
}

#endif /* SQUID_HTTP_UPGRADE_H */

