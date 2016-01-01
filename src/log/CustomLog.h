/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CUSTOMLOG_H_
#define SQUID_CUSTOMLOG_H_

//#include "format/Format.h"
#include "acl/forward.h"
#include "log/Formats.h"

class Logfile;
namespace Format
{
class Format;
}

/// representaiton of a custom log directive. Currently a POD.
class CustomLog
{
public:
    char *filename;
    ACLList *aclList;
    Format::Format *logFormat;
    Logfile *logfile;
    CustomLog *next;
    Log::Format::log_type type;
    /// how much to buffer before dropping or dying (access_log buffer-size)
    size_t bufferSize;
    /// whether unrecoverable errors (e.g., dropping a log record) kill worker
    bool fatal;
};

#endif /* SQUID_CUSTOMLOG_H_ */

