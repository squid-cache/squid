/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPACCESSLOGENTRY_H
#define SQUID_HTTPACCESSLOGENTRY_H

#include "anyp/PortCfg.h"
#include "base/RefCount.h"
#include "comm/Connection.h"
#include "HierarchyLogEntry.h"
#include "http/ProtocolVersion.h"
#include "http/RequestMethod.h"
#include "HttpHeader.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "MessageSizes.h"
#include "Notes.h"
#include "sbuf/SBuf.h"
#if ICAP_CLIENT
#include "adaptation/icap/Elements.h"
#endif
#if USE_OPENSSL
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

    AccessLogEntry() :
        url(nullptr),
        lastAclName(nullptr),
        reply(nullptr),
        request(nullptr),
        adapted_request(nullptr)
    {}
    ~AccessLogEntry();

    /// Fetch the client IP log string into the given buffer.
    /// Knows about several alternate locations of the IP
    /// including indirect forwarded-for IP if configured to log that
    void getLogClientIp(char *buf, size_t bufsz) const;

    /// Fetch the transaction method string (ICP opcode, HTCP opcode or HTTP method)
    SBuf getLogMethod() const;

    SBuf url;

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
        HttpDetails() :
            method(Http::METHOD_NONE),
            code(0),
            content_type(NULL),
            clientRequestSz(),
            clientReplySz() {}

        HttpRequestMethod method;
        int code;
        const char *content_type;
        AnyP::ProtocolVersion version;

        /// counters for the original request received from client
        // TODO calculate header and payload better (by parser)
        // XXX payload encoding overheads not calculated at all yet.
        MessageSizes clientRequestSz;

        /// counters for the response sent to client
        // TODO calculate header and payload better (by parser)
        // XXX payload encoding overheads not calculated at all yet.
        MessageSizes clientReplySz;

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

#if USE_OPENSSL
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
            highOffset(0),
            objectSize(0),
            code(LOG_TAG_NONE),
            rfc931 (NULL),
            extuser(NULL),
#if USE_OPENSSL
            ssluser(NULL),
#endif
            port(NULL)
        {
            caddr.setNoAddr();
            memset(&start_time, 0, sizeof(start_time));
            memset(&trTime, 0, sizeof(start_time));
        }

        Ip::Address caddr;
        int64_t highOffset;
        int64_t objectSize;
        LogTags code;
        struct timeval start_time; ///< The time the master transaction started
        struct timeval trTime; ///< The response time
        const char *rfc931;
        const char *extuser;
#if USE_OPENSSL

        const char *ssluser;
        Security::CertPointer sslClientCert; ///< cert received from the client
#endif
        AnyP::PortCfgPointer port;

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

    const char *lastAclName; ///< string for external_acl_type %ACL format code
    SBuf lastAclData; ///< string for external_acl_type %DATA format code

    HierarchyLogEntry hier;
    HttpReply *reply;
    HttpRequest *request; //< virgin HTTP request
    HttpRequest *adapted_request; //< HTTP request after adaptation and redirection

    /// key:value pairs set by squid.conf note directive and
    /// key=value pairs returned from URL rewrite/redirect helper
    NotePairs::Pointer notes;

#if ICAP_CLIENT
    /** \brief This subclass holds log info for ICAP part of request
     *  \todo Inner class declarations should be moved outside
     */
    class IcapLogEntry
    {
    public:
        IcapLogEntry() : reqMethod(Adaptation::methodNone), bytesSent(0), bytesRead(0),
            bodyBytesRead(-1), request(NULL), reply(NULL),
            outcome(Adaptation::Icap::xoUnknown), resStatus(Http::scNone)
        {
            memset(&trTime, 0, sizeof(trTime));
            memset(&ioTime, 0, sizeof(ioTime));
            memset(&processingTime, 0, sizeof(processingTime));
        }

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
        struct timeval trTime;
        /** \brief Transaction I/O time.
         * The timer starts when the first ICAP request
         * byte is scheduled for sending and stops when the lastbyte of the
         * ICAP response is received.
         */
        struct timeval ioTime;
        Http::StatusCode resStatus;   ///< ICAP response status code
        struct timeval processingTime;      ///< total ICAP processing time
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

