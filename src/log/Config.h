/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOG_CONFIG_H
#define SQUID_SRC_LOG_CONFIG_H

#include "format/Format.h"

class StoreEntry;

namespace Log
{

class LogConfig
{
public:
    void parseFormats();
    void dumpFormats(StoreEntry *e, const char *name) {
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

#endif

