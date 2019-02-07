/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_LOG_FORMATS_H
#define _SQUID_LOG_FORMATS_H

#include "AccessLogEntry.h"
#include "base/RefCount.h"

typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class AccessLogEntry;
class CustomLog;
class Logfile;

namespace Log
{

namespace Format
{

typedef enum {
    CLF_UNKNOWN,
    CLF_COMBINED,
    CLF_COMMON,
    CLF_CUSTOM,
#if ICAP_CLIENT
    CLF_ICAP_SQUID,
#endif
    CLF_REFERER,
    CLF_SQUID,
    CLF_USERAGENT,
    CLF_NONE
} log_type;

/// Native Squid Format Display
void SquidNative(const AccessLogEntryPointer &al, Logfile * logfile);

/// Display log details in Squid ICAP format.
void SquidIcap(const AccessLogEntryPointer &al, Logfile * logfile);

/// Display log details in useragent format.
void SquidUserAgent(const AccessLogEntryPointer &al, Logfile * logfile);

/// Display log details in Squid old refererlog format.
void SquidReferer(const AccessLogEntryPointer &al, Logfile * logfile);

/// Log with a local custom format
void SquidCustom(const AccessLogEntryPointer &al, CustomLog * log);

/// Log with Apache httpd common format
void HttpdCommon(const AccessLogEntryPointer &al, Logfile * logfile);

/// Log with Apache httpd combined format
void HttpdCombined(const AccessLogEntryPointer &al, Logfile * logfile);

}; // namespace Format
}; // namespace Log

#endif /* _SQUID_LOG_FORMATS_H */

