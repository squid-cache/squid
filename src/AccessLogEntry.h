/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPACCESSLOGENTRY_H
#define SQUID_HTTPACCESSLOGENTRY_H

#include "anyp/PortCfg.h"
#include "base/CodeContext.h"
#include "comm/Connection.h"
#include "error/Error.h"
#include "HierarchyLogEntry.h"
#include "http/ProtocolVersion.h"
#include "http/RequestMethod.h"
#include "HttpHeader.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "MessageSizes.h"
#include "Notes.h"
#include "proxyp/forward.h"
#include "sbuf/SBuf.h"
#if ICAP_CLIENT
#include "adaptation/icap/Elements.h"
#endif
#if USE_OPENSSL
#include "ssl/gadgets.h"
#include "ssl/support.h"
#endif

/* forward decls */
class HttpReply;
class HttpRequest;
class CustomLog;

class AccessLogEntry: public CodeContext
{

public:
    typedef RefCount<AccessLogEntry> Pointer;

    AccessLogEntry();
    ~AccessLogEntry() override;

    /* CodeContext API */
    std::ostream &detailCodeContext(std::ostream &os) const override;
    ScopedId codeContextGist() const override;

    /// Fetch the client IP log string into the given buffer.
    /// Knows about several alternate locations of the IP
    /// including indirect forwarded-for IP if configured to log that
    void getLogClientIp(char *buf, size_t bufsz) const;

    /// %>A: Compute client FQDN if possible, using the supplied buf if needed.
    /// \returns result for immediate logging (not necessarily pointing to buf)
    /// Side effect: Enables reverse DNS lookups of future client addresses.
    const char *getLogClientFqdn(char *buf, size_t bufSize) const;

    /// Fetch the client IDENT string, or nil if none is available.
    const char *getClientIdent() const;

    /// Fetch the external ACL provided 'user=' string, or nil if none is available.
    const char *getExtUser() const;

    /// whether we know what the request method is
    bool hasLogMethod() const { return icp.opcode || htcp.opcode || http.method; }

    /// Fetch the transaction method string (ICP opcode, HTCP opcode or HTTP method)
    SBuf getLogMethod() const;

    void syncNotes(HttpRequest *request);

    /// dump all reply headers (for sending or risky logging)
    void packReplyHeaders(MemBuf &mb) const;

    SBuf url;

    /// TCP/IP level details about the client connection
    Comm::ConnectionPointer tcpClient;
    // TCP/IP level details about the server or peer connection
    // are stored in hier.tcpServer

    /** \brief This subclass holds log info for HTTP protocol
     * TODO: Inner class declarations should be moved outside
     * TODO: details of HTTP held in the parent class need moving into here.
     */
    class HttpDetails
    {

    public:
        HttpRequestMethod method;
        int code = 0;
        const char *content_type = nullptr;
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
     * TODO: Inner class declarations should be moved outside
     */
    class IcpDetails
    {
    public:
        icp_opcode opcode = ICP_INVALID;
    } icp;

    /** \brief This subclass holds log info for HTCP protocol
     * TODO: Inner class declarations should be moved outside
     */
    class HtcpDetails
    {
    public:
        const char *opcode = nullptr;
    } htcp;

#if USE_OPENSSL
    /// logging information specific to the SSL protocol
    class SslDetails
    {
    public:
        const char *user = nullptr; ///< emailAddress from the SSL client certificate
        int bumpMode = ::Ssl::bumpEnd; ///< whether and how the request was SslBumped
    } ssl;
#endif

    /** \brief This subclass holds log info for Squid internal stats
     * TODO: Inner class declarations should be moved outside
     * TODO: some details relevant to particular protocols need shuffling to other sub-classes
     * TODO: this object field need renaming to 'squid' or something.
     */
    class CacheDetails
    {
    public:
        CacheDetails() {
            caddr.setNoAddr();
            memset(&start_time, 0, sizeof(start_time));
            memset(&trTime, 0, sizeof(start_time));
        }

        Ip::Address caddr;
        int64_t highOffset = 0;
        int64_t objectSize = 0;
        LogTags code;
        struct timeval start_time; ///< The time the master transaction started
        struct timeval trTime; ///< The response time
        const char *rfc931 = nullptr;
        const char *extuser = nullptr;
#if USE_OPENSSL
        const char *ssluser = nullptr;
        Security::CertPointer sslClientCert; ///< cert received from the client
#endif
        AnyP::PortCfgPointer port;
    } cache;

    /** \brief This subclass holds log info for various headers in raw format
     * TODO: shuffle this to the relevant protocol section.
     */
    class Headers
    {
    public:
        char *request = nullptr; //< virgin HTTP request headers
        char *adapted_request = nullptr; //< HTTP request headers after adaptation and redirection
    } headers;

#if USE_ADAPTATION
    /** \brief This subclass holds general adaptation log info.
     * TODO: Inner class declarations should be moved outside.
     */
    class AdaptationDetails
    {
    public:
        /// image of the last ICAP response header or eCAP meta received
        char *last_meta = nullptr;
    } adapt;
#endif

    const char *lastAclName = nullptr; ///< string for external_acl_type %ACL format code
    SBuf lastAclData; ///< string for external_acl_type %DATA format code

    HierarchyLogEntry hier;
    HttpReplyPointer reply;
    HttpRequest *request = nullptr; //< virgin HTTP request
    HttpRequest *adapted_request = nullptr; //< HTTP request after adaptation and redirection

    /// key:value pairs set by squid.conf note directive and
    /// key=value pairs returned from URL rewrite/redirect helper
    NotePairs::Pointer notes;

    /// The total number of finished attempts to establish a connection.
    /// Excludes discarded HappyConnOpener attempts. Includes failed
    /// HappyConnOpener attempts and [always successful] persistent connection
    /// reuse. See %request_attempts.
    int requestAttempts = 0;

    /// see ConnStateData::proxyProtocolHeader_
    ProxyProtocol::HeaderPointer proxyProtocolHeader;

#if ICAP_CLIENT
    /** \brief This subclass holds log info for ICAP part of request
     *  TODO: Inner class declarations should be moved outside
     */
    class IcapLogEntry
    {
    public:
        IcapLogEntry() {
            memset(&trTime, 0, sizeof(trTime));
            memset(&ioTime, 0, sizeof(ioTime));
            memset(&processingTime, 0, sizeof(processingTime));
        }

        Ip::Address hostAddr; ///< ICAP server IP address
        String serviceName;        ///< ICAP service name
        String reqUri;             ///< ICAP Request-URI
        Adaptation::Icap::ICAP::Method reqMethod = Adaptation::methodNone; ///< ICAP request method
        int64_t bytesSent = 0;       ///< number of bytes sent to ICAP server so far
        int64_t bytesRead = 0;       ///< number of bytes read from ICAP server so far
        /**
         * number of ICAP body bytes read from ICAP server or -1 for no encapsulated
         * message data in ICAP reply (eg 204 responses)
         */
        int64_t bodyBytesRead = -1;
        HttpRequest* request = nullptr;    ///< ICAP request
        HttpReply* reply = nullptr;        ///< ICAP reply

        Adaptation::Icap::XactOutcome outcome = Adaptation::Icap::xoUnknown; ///< final transaction status
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
        Http::StatusCode resStatus = Http::scNone;   ///< ICAP response status code
        struct timeval processingTime;      ///< total ICAP processing time
    }
    icap;
#endif

    /// Effective URI of the received client (or equivalent) HTTP request or,
    /// in rare cases where that information was not collected, a nil pointer.
    /// Receiving errors are represented by "error:..." URIs.
    /// Adaptations and redirections do not affect this URI.
    const SBuf *effectiveVirginUrl() const;

    /// Remember Client URI (or equivalent) when there is no HttpRequest.
    void setVirginUrlForMissingRequest(const SBuf &vu)
    {
        if (!request)
            virginUrlForMissingRequest_ = vu;
    }

    /// \returns stored transaction error information (or nil)
    const Error *error() const;

    /// sets (or updates the already stored) transaction error as needed
    void updateError(const Error &);

private:
    /// transaction problem
    /// if set, overrides (and should eventually replace) request->error
    Error error_;

    /// Client URI (or equivalent) for effectiveVirginUrl() when HttpRequest is
    /// missing. This member is ignored unless the request member is nil.
    SBuf virginUrlForMissingRequest_;
};

class ACLChecklist;
class StoreEntry;

/* Should be in 'AccessLog.h' as the driver */
void accessLogLogTo(CustomLog *, const AccessLogEntryPointer &, ACLChecklist *checklist = nullptr);
void accessLogLog(const AccessLogEntryPointer &, ACLChecklist *);
void accessLogRotate(void);
void accessLogClose(void);
void accessLogInit(void);
const char *accessLogTime(time_t);

#endif /* SQUID_HTTPACCESSLOGENTRY_H */

