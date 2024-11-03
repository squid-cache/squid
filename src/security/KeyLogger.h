/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_KEYLOGGER_H
#define SQUID_SRC_SECURITY_KEYLOGGER_H

#include "acl/forward.h"
#include "security/CommunicationSecrets.h"

#include <iosfwd>

class MasterXaction;
typedef RefCount<MasterXaction> MasterXactionPointer;

namespace Security {

/// manages collecting and logging secrets of a TLS connection to tls_key_log
class KeyLogger
{
public:
    /// (quickly decides whether logging might be needed and) logs if possible
    /// this method is a performance optimization wrapper for slower maybeLog()
    void checkpoint(const Connection &, const Acl::ChecklistFiller &);

private:
    /// (slowly checks logging preconditions and) logs if possible
    void maybeLog(const Connection &, const Acl::ChecklistFiller &);

    /// (slowly checks) whether logging is possible now
    bool shouldLog(const Acl::ChecklistFiller &) const;

    /// connection secrets learned so far
    CommunicationSecrets secrets;

    /// whether to prevent further logging attempts
    bool done_ = false;

    /// whether we know that the admin wants us to log this connection keys
    mutable bool wanted_ = false;
};

} // namespace Security

inline void
Security::KeyLogger::checkpoint(const Connection &sconn, const Acl::ChecklistFiller &caller)
{
    if (!done_)
        maybeLog(sconn, caller);
}

#endif /* SQUID_SRC_SECURITY_KEYLOGGER_H */

