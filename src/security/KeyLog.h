/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_KEYLOG_H
#define SQUID_SRC_SECURITY_KEYLOG_H

#include "log/CustomLog.h"
#include "log/forward.h"
#include "sbuf/SBuf.h"
#include "security/forward.h"

namespace Security {

/// a single tls_key_log directive configuration and logging handler
class KeyLog: public FormattedLog
{
public:
    explicit KeyLog(ConfigParser&);

    /// whether record() preconditions are currently satisfied
    bool canLog() const { return logfile != nullptr; }

    /// writes a single (but multi-line) key log entry
    void record(const CommunicationSecrets &);

    /// reproduces explicitly-configured squid.conf settings
    void dump(std::ostream &) const;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_KEYLOG_H */

