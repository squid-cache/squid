#ifndef SQUID_CUSTOMLOG_H_
#define SQUID_CUSTOMLOG_H_
/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
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
