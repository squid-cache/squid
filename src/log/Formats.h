#ifndef _SQUID_LOG_FORMATS_H
#define _SQUID_LOG_FORMATS_H

class AccessLogEntry;
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
void SquidNative(AccessLogEntry * al, Logfile * logfile);

/// Display log details in Squid ICAP format.
void SquidIcap(AccessLogEntry * al, Logfile * logfile);

/// Display log details in useragent format.
void SquidUserAgent(AccessLogEntry * al, Logfile * logfile);

/// Display log details in Squid old refererlog format.
void SquidReferer(AccessLogEntry * al, Logfile * logfile);

/// Log with a local custom format
void SquidCustom(AccessLogEntry * al, customlog * log);

/// Log with Apache httpd common format
void HttpdCommon(AccessLogEntry * al, Logfile * logfile);

/// Log with Apache httpd combined format
void HttpdCombined(AccessLogEntry * al, Logfile * logfile);

}; // namespace Format
}; // namespace Log

#endif /* _SQUID_LOG_FORMATS_H */
