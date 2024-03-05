/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOG_CONFIG_H
#define SQUID_SRC_LOG_CONFIG_H

#include "format/Format.h"
#include "log/Formats.h"

class StoreEntry;

namespace Log
{

class LogConfig
{
public:
    /// \returns the name of the given built-in logformat type (or nil)
    static const char *BuiltInFormatName(Format::log_type type);

    /// \returns either a named built-in logformat ID or CLF_UNKNOWN
    static Format::log_type FindBuiltInFormat(const char *logformatName);
    static_assert(!Log::Format::CLF_UNKNOWN, "FindBuiltInFormat(unknown) is falsy");

    /// \returns a named (previously configured) custom log format object or nil
    ::Format::Format *findCustomFormat(const char *logformatName) const;

    /// whether the given format name is supported, either as a built-in or a
    /// (previously configured) custom logformat
    bool knownFormat(const char *logformatName) const;

    void parseFormats();
    void dumpFormats(StoreEntry *e, const char *name) {
        if (logformats)
            logformats->dump(e, name);
    }

    /// File path to logging daemon executable
    char *logfile_daemon;

    /// Linked list of custom log formats
    ::Format::Format *logformats;

#if USE_ADAPTATION
    bool hasAdaptToken;
#endif

#if ICAP_CLIENT
    bool hasIcapToken;
#endif
};

extern LogConfig TheConfig;

} // namespace Log

// Legacy parsing wrappers
#define parse_logformat(X)  (X)->parseFormats()
#define free_logformat(X)   do{ delete (*X).logformats; (*X).logformats=NULL; }while(false)
#define dump_logformat(E,N,D) (D).dumpFormats((E),(N))

#endif /* SQUID_SRC_LOG_CONFIG_H */

