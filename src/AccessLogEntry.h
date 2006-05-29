
/*
 * $Id: AccessLogEntry.h,v 1.5 2006/05/29 00:14:59 robertc Exp $
 *
 *
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_HTTPACCESSLOGENTRY_H
#define SQUID_HTTPACCESSLOGENTRY_H

#include "HttpVersion.h"
#include "HierarchyLogEntry.h"

/* forward decls */

class CacheManager;

class AccessLogEntry
{

public:
    AccessLogEntry() : url(NULL) , reply(NULL), request(NULL) {}

    const char *url;

    class HttpDetails
    {

    public:
        HttpDetails() : method(METHOD_NONE), code(0), content_type(NULL) {}

        method_t method;
        int code;
        const char *content_type;
        HttpVersion version;
    }

    http;

    class ICPDetails
    {

    public:
        ICPDetails() : opcode(ICP_INVALID) {}

        icp_opcode opcode;
    }

    icp;

    class CacheDetails
    {

    public:
        CacheDetails() : size(0),
                highOffset(0),
                objectSize(0),
                code (LOG_TAG_NONE),
                msec(0),
                rfc931 (NULL),
                authuser (NULL),
                extuser(NULL)
#if USE_SSL
                ,ssluser(NULL)
#endif
        {
            memset(&caddr, '\0', sizeof(caddr));
        }

        struct IN_ADDR caddr;
        size_t size;
        off_t highOffset;
        size_t objectSize;
        log_type code;
        int msec;
        const char *rfc931;
        const char *authuser;
        const char *extuser;
#if USE_SSL

        const char *ssluser;
#endif

    }

    cache;

    class Headers
    {

    public:
        Headers() : request(NULL), reply(NULL) {}

        char *request;
        char *reply;
    }

    headers;

    class Private
    {

    public:
        Private() : method_str(NULL) {}

        const char *method_str;
    }

    _private;
    HierarchyLogEntry hier;
    HttpReply *reply;
    HttpRequest *request;
};

/* Should be in 'AccessLog.h' as the driver */
extern void accessLogLog(AccessLogEntry *, ACLChecklist * checklist);
extern void accessLogRotate(void);
extern void accessLogClose(void);
extern void accessLogInit(void);
extern void accessLogRegisterWithCacheManager(CacheManager & manager);
extern void accessLogFreeMemory(AccessLogEntry * aLogEntry);
extern const char *accessLogTime(time_t);
extern int accessLogParseLogFormat(logformat_token ** fmt, char *def);
extern void accessLogDumpLogFormat(StoreEntry * entry, const char *name, logformat * definitions);
extern void accessLogFreeLogFormat(logformat_token ** fmt);

#endif /* SQUID_HTTPACCESSLOGENTRY_H */
