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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */
#ifndef SQUID_HTTPACCESSLOGENTRY_H
#define SQUID_HTTPACCESSLOGENTRY_H

#include "HttpVersion.h"
#include "HttpRequestMethod.h"
#include "HierarchyLogEntry.h"
#include "ip/IpAddress.h"
#include "HttpRequestMethod.h"
#if ICAP_CLIENT
#include "adaptation/icap/Elements.h"
#endif

/* forward decls */
class HttpReply;
class HttpRequest;

class AccessLogEntry
{

public:
    AccessLogEntry() : url(NULL) , reply(NULL), request(NULL) {}

    const char *url;

    class HttpDetails
    {

    public:
        HttpDetails() : method(METHOD_NONE), code(0), content_type(NULL) {}

        HttpRequestMethod method;
        int code;
        const char *content_type;
        HttpVersion version;
    } http;

    class ICPDetails
    {

    public:
        ICPDetails() : opcode(ICP_INVALID) {}

        icp_opcode opcode;
    } icp;

    class HtcpDetails
    {
    public:
        HtcpDetails() : opcode(NULL) {};

        const char *opcode;
    } htcp;

    class CacheDetails
    {

    public:
        CacheDetails() : caddr(),
                requestSize(0),
                replySize(0),
                requestHeadersSize(0),
                replyHeadersSize(0),
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
        {;
        }

        IpAddress caddr;
        int64_t requestSize;
        int64_t replySize;
        int requestHeadersSize; ///< received, including request line
        int replyHeadersSize; ///< sent, including status line
        int64_t highOffset;
        int64_t objectSize;
        log_type code;
        int msec;
        const char *rfc931;
        const char *authuser;
        const char *extuser;
#if USE_SSL

        const char *ssluser;
#endif

    } cache;

    class Headers
    {

    public:
        Headers() : request(NULL),
#if ICAP_CLIENT
                    icap(NULL),
#endif
                    reply(NULL) {}

        char *request;

#if ICAP_CLIENT
        char * icap;    ///< last matching ICAP response header.
#endif
        char *reply;
    } headers;

    // Why is this a sub-class and not a set of real "private:" fields?
    // It looks like its duplicating HTTPRequestMethod anyway!
    class Private
    {

    public:
        Private() : method_str(NULL) {}

        const char *method_str;
    } _private;
    HierarchyLogEntry hier;
    HttpReply *reply;
    HttpRequest *request;

#if ICAP_CLIENT
    /** \brief This subclass holds log info for ICAP part of request
     *  \todo Inner class declarations should be moved outside
     */
    class IcapLogEntry {
    public:
    IcapLogEntry():request(NULL),reply(NULL),outcome(Adaptation::Icap::xoUnknown),trTime(0),ioTime(0),resStatus(HTTP_STATUS_NONE){}

        IpAddress hostAddr; ///< ICAP server IP address
        String serviceName;        ///< ICAP service name
        String reqUri;             ///< ICAP Request-URI
        Adaptation::Icap::ICAP::Method reqMethod; ///< ICAP request method
        int64_t bytesSent;       ///< number of bytes sent to ICAP server so far
        int64_t bytesRead;       ///< number of bytes read from ICAP server so far
        HttpRequest* request;    ///< ICAP request
        HttpReply* reply;        ///< ICAP reply

        Adaptation::Icap::XactOutcome outcome; ///< final transaction status
        /** \brief Transaction response time.
         * The timer starts when the ICAP transaction
         *  is created and stops when the result of the transaction is logged
         */
        int trTime;
        /** \brief Transaction I/O time.
         * The timer starts when the first ICAP request
         * byte is scheduled for sending and stops when the lastbyte of the 
         * ICAP response is received.
         */
        int ioTime;
        http_status resStatus;   ///< ICAP response status code
        int processingTime;      ///< total ICAP processing time in milliseconds
    }
    icap;
#endif
};

class ACLChecklist;
class StoreEntry;
class logformat_token;

/* Should be in 'AccessLog.h' as the driver */
extern void accessLogLogTo(customlog* log, AccessLogEntry* al, ACLChecklist* checklist = NULL);
extern void accessLogLog(AccessLogEntry *, ACLChecklist * checklist);
extern void accessLogRotate(void);
extern void accessLogClose(void);
extern void accessLogInit(void);
extern void accessLogFreeMemory(AccessLogEntry * aLogEntry);
extern const char *accessLogTime(time_t);
extern int accessLogParseLogFormat(logformat_token ** fmt, char *def);
extern void accessLogDumpLogFormat(StoreEntry * entry, const char *name, logformat * definitions);
extern void accessLogFreeLogFormat(logformat_token ** fmt);

#endif /* SQUID_HTTPACCESSLOGENTRY_H */
