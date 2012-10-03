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

#include "anyp/PortCfg.h"
#include "comm/Connection.h"
#include "HttpVersion.h"
#include "HttpRequestMethod.h"
#include "HierarchyLogEntry.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "HttpRequestMethod.h"
#if ICAP_CLIENT
#include "adaptation/icap/Elements.h"
#endif
#include "RefCount.h"
#if USE_SSL
#include "ssl/gadgets.h"
#endif

/* forward decls */
class HttpReply;
class HttpRequest;
class CustomLog;

class AccessLogEntry: public RefCountable
{

public:
    typedef RefCount<AccessLogEntry> Pointer;

    AccessLogEntry() : url(NULL), tcpClient(), reply(NULL), request(NULL),
            adapted_request(NULL) {}
    ~AccessLogEntry();

    /// Fetch the client IP log string into the given buffer.
    /// Knows about several alternate locations of the IP
    /// including indirect forwarded-for IP if configured to log that
    void getLogClientIp(char *buf, size_t bufsz) const;

    const char *url;

    /// TCP/IP level details about the client connection
    Comm::ConnectionPointer tcpClient;
    // TCP/IP level details about the server or peer connection
    // are stored in hier.tcpServer

    /** \brief This subclass holds log info for HTTP protocol
     * \todo Inner class declarations should be moved outside
     * \todo details of HTTP held in the parent class need moving into here.
     */
    class HttpDetails
    {

    public:
        HttpDetails() : method(METHOD_NONE), code(0), content_type(NULL),
                timedout(false), aborted(false) {}

        HttpRequestMethod method;
        int code;
        const char *content_type;
        HttpVersion version;
        bool timedout; ///< terminated due to a lifetime or I/O timeout
        bool aborted; ///< other abnormal termination (e.g., I/O error)

        /// compute suffix for the status access.log field
        const char *statusSfx() const {
            return timedout ? "_TIMEDOUT" : (aborted ? "_ABORTED" : "");
        }
    } http;

    /** \brief This subclass holds log info for ICP protocol
     * \todo Inner class declarations should be moved outside
     */
    class IcpDetails
    {

    public:
        IcpDetails() : opcode(ICP_INVALID) {}

        icp_opcode opcode;
    } icp;

    /** \brief This subclass holds log info for HTCP protocol
     * \todo Inner class declarations should be moved outside
     */
    class HtcpDetails
    {
    public:
        HtcpDetails() : opcode(NULL) {};

        const char *opcode;
    } htcp;

#if USE_SSL
    /// logging information specific to the SSL protocol
    class SslDetails
    {
    public:
        SslDetails();

        const char *user; ///< emailAddress from the SSL client certificate
        int bumpMode; ///< whether and how the request was SslBumped
    } ssl;
#endif

    /** \brief This subclass holds log info for Squid internal stats
     * \todo Inner class declarations should be moved outside
     * \todo some details relevant to particular protocols need shuffling to other sub-classes
     * \todo this object field need renaming to 'squid' or something.
     */
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
                extuser(NULL),
#if USE_SSL
                ssluser(NULL),
#endif
                port(NULL) {
            ;
        }

        Ip::Address caddr;
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
        Ssl::X509_Pointer sslClientCert; ///< cert received from the client
#endif
        AnyP::PortCfg *port;

    } cache;

    /** \brief This subclass holds log info for various headers in raw format
     * \todo shuffle this to the relevant protocol section.
     */
    class Headers
    {

    public:
        Headers() : request(NULL),
                adapted_request(NULL),
                reply(NULL) {}

        char *request; //< virgin HTTP request headers

        char *adapted_request; //< HTTP request headers after adaptation and redirection

        char *reply;
    } headers;

#if USE_ADAPTATION
    /** \brief This subclass holds general adaptation log info.
     * \todo Inner class declarations should be moved outside.
     */
    class AdaptationDetails
    {

    public:
        AdaptationDetails(): last_meta(NULL) {}

        /// image of the last ICAP response header or eCAP meta received
        char *last_meta;
    } adapt;
#endif

    // Why is this a sub-class and not a set of real "private:" fields?
    // It looks like its duplicating HTTPRequestMethod anyway!
    // TODO: shuffle this to the relevant protocol section OR replace with request->method
    class Private
    {

    public:
        Private() : method_str(NULL) {}

        const char *method_str;
    } _private;
    HierarchyLogEntry hier;
    HttpReply *reply;
    HttpRequest *request; //< virgin HTTP request
    HttpRequest *adapted_request; //< HTTP request after adaptation and redirection

#if ICAP_CLIENT
    /** \brief This subclass holds log info for ICAP part of request
     *  \todo Inner class declarations should be moved outside
     */
    class IcapLogEntry
    {
    public:
        IcapLogEntry():bodyBytesRead(-1),request(NULL),reply(NULL),outcome(Adaptation::Icap::xoUnknown),trTime(0),ioTime(0),resStatus(HTTP_STATUS_NONE) {}

        Ip::Address hostAddr; ///< ICAP server IP address
        String serviceName;        ///< ICAP service name
        String reqUri;             ///< ICAP Request-URI
        Adaptation::Icap::ICAP::Method reqMethod; ///< ICAP request method
        int64_t bytesSent;       ///< number of bytes sent to ICAP server so far
        int64_t bytesRead;       ///< number of bytes read from ICAP server so far
        /**
         * number of ICAP body bytes read from ICAP server or -1 for no encapsulated
         * message data in ICAP reply (eg 204 responses)
         */
        int64_t bodyBytesRead;
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

/* Should be in 'AccessLog.h' as the driver */
void accessLogLogTo(CustomLog* log, AccessLogEntry::Pointer &al, ACLChecklist* checklist = NULL);
void accessLogLog(AccessLogEntry::Pointer &, ACLChecklist * checklist);
void accessLogRotate(void);
void accessLogClose(void);
void accessLogInit(void);
const char *accessLogTime(time_t);

#endif /* SQUID_HTTPACCESSLOGENTRY_H */
