/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "debug/Stream.h"
#include "log/Config.h"
#include "log/File.h"
#include "log/FormattedLog.h"
#include "Parsing.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

FormattedLog::~FormattedLog()
{
    close(); // TODO: destructing a Logfile object should be enough
    aclDestroyAclList(&aclList);
    safe_free(filename);
    // leave logFormat alone -- we do not own that object
}

bool
FormattedLog::usesDaemon() const
{
    return (filename && strncmp(filename, "daemon:", 7) == 0);
}

void
FormattedLog::parseOptions(ConfigParser &parser, const char *defaultFormatName)
{
    const char *explicitFormatName = nullptr;
    char *key = nullptr;
    char *value = nullptr;
    while (parser.optionalKvPair(key, value)) {

        if (strcmp(key, "on-error") == 0) {
            if (strcmp(value, "die") == 0) {
                fatal = true;
            } else if (strcmp(value, "drop") == 0) {
                fatal = false;
            } else {
                throw TextException(ToSBuf("unsupported ", cfg_directive, " on-error value: ", value,
                                           Debug::Extra, "expected 'drop' or 'die'"), Here());
            }
            continue;
        }

        if (strcmp(key, "buffer-size") == 0) {
            parseBytesOptionValue(&bufferSize, "bytes", value);
            continue;
        }

        if (strcmp(key, "rotate") == 0) {
            rotationsToKeep = std::optional<unsigned int>(xatoui(value));
            continue;
        }

        if (strcmp(key, "logformat") == 0 && defaultFormatName) {
            if (explicitFormatName)
                throw TextException(ToSBuf("duplicated ", cfg_directive, " option: ", key), Here());

            explicitFormatName = value;
            continue;
        }

        throw TextException(ToSBuf("unsupported ", cfg_directive, " option: ", key, "=", value), Here());
    }

    if (const auto formatName = explicitFormatName ? explicitFormatName : defaultFormatName) {
        assert(defaultFormatName); // this log supports logformat=name
        setLogformat(formatName);
    } // else OK: this log does not support logformat=name and none was given
}

void
FormattedLog::dumpOptions(std::ostream &os) const
{
    /* do not report defaults */

    // TODO: Here and elsewhere, report both explicitly configured settings and
    // various defaults. Properly excluding defaults requires wrapping most
    // non-pointer members in std::optional and adding methods to compute the final
    // option value after accounting for defaults (and those may change with
    // reconfiguration!). And all that effort may still not result in a faithful
    // reproduction of the original squid.conf because of size unit changes,
    // order changes, duplicates removal, etc. More importantly, these reports
    // are much more useful for determining complete Squid state (especially
    // when triaging older Squids with some difficult-to-figure-out defaults).

    switch (type) {
    case Log::Format::CLF_UNKNOWN:
        break; // do not report a format when it was not configured

    case Log::Format::CLF_NONE:
        break; // the special "none" case has no format to report

    case Log::Format::CLF_SQUID:
        break; // do not report default format (XXX: icap_log default differs)

    case Log::Format::CLF_CUSTOM:
        if (logFormat) // paranoid; the format should be set
            os << " logformat=" << logFormat->name;
        break;

    default:
        os << " logformat=" << Log::LogConfig::BuiltInFormatName(type);
    }

    if (!fatal)
        os << " on-error=drop";

    if (bufferSize != 8*MAX_URL)
        os << " buffer-size=" << bufferSize << "bytes";

    if (rotationsToKeep)
        os << " rotate=" << rotationsToKeep.value();
}

void
FormattedLog::setLogformat(const char *logformatName)
{
    assert(logformatName);
    assert(type == Log::Format::CLF_UNKNOWN); // set only once
    assert(!logFormat); // set only once

    debugs(3, 7, "possible " << filename << " logformat: " << logformatName);

    if (const auto lf = Log::TheConfig.findCustomFormat(logformatName)) {
        type = Log::Format::CLF_CUSTOM;
        logFormat = lf;
        return;
    }

    if (const auto id = Log::LogConfig::FindBuiltInFormat(logformatName)) {
        type = id;
        return;
    }

    throw TextException(ToSBuf("unknown logformat name in ", cfg_directive, ": ", logformatName), Here());
}

void
FormattedLog::open()
{
    Must(!logfile);
    Must(filename);
    logfile = logfileOpen(filename, bufferSize, fatal);
    // the opening code reports failures and returns nil if they are non-fatal
}

void
FormattedLog::rotate()
{
    if (logfile)
        logfileRotate(logfile, rotationsToKeep.value_or(Config.Log.rotateNumber));
}

void
FormattedLog::close()
{
    if (logfile) {
        logfileClose(logfile);
        logfile = nullptr; // deleted by the closing code
    }
}

