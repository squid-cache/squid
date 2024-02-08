/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOG_FORMATTEDLOG_H
#define SQUID_SRC_LOG_FORMATTEDLOG_H

#include "acl/forward.h"
#include "log/Formats.h"
#include "log/forward.h"

#include <iosfwd>
#include <optional>

class ConfigParser;

/// A single-destination, single-record-format log.
/// The customizable destination is based on Logfile "logging modules" API.
/// Some logs allow the admin to select or specify the record format.
class FormattedLog
{
public:
    FormattedLog() = default;
    ~FormattedLog();

    FormattedLog(FormattedLog &&) = delete; // no need to support copying of any kind

    /// \returns whether the daemon module is used for this log
    bool usesDaemon() const;

    /// handles the [key=value...] part of the log configuration
    /// \param defaultFormat default logformat or, to force built-in format, nil
    void parseOptions(ConfigParser&, const char *defaultFormat);

    /// reports explicitly-configured key=value options, in squid.conf format
    void dumpOptions(std::ostream &os) const;

    /// configures formatting-related settings for the given logformat name
    void setLogformat(const char *logformatName);

    /// prepare for recording entries
    void open();

    /// handle the log rotation request
    void rotate();

    /// stop recording entries
    void close();

    /// records writer
    Logfile *logfile = nullptr;

    /// logging destination
    char *filename = nullptr;

    /// restrict logging to matching transactions
    ACLList *aclList = nullptr;

    /// custom log record template for type == Log::Format::CLF_CUSTOM
    Format::Format *logFormat = nullptr;

    /// log record template ID
    Log::Format::log_type type = Log::Format::CLF_UNKNOWN;

    /// how much to buffer before dropping or dying (buffer-size=N)
    size_t bufferSize = 8*MAX_URL;

    /// how many log files to retain when rotating. Default: obey logfile_rotate
    std::optional<unsigned int> rotationsToKeep;

    /// whether unrecoverable errors (e.g., dropping a log record) kill worker
    bool fatal = true;
};

#endif /* SQUID_SRC_LOG_FORMATTEDLOG_H */

