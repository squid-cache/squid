/*
 * DEBUG: section 33    Client-side Routines
 * AUTHOR: Duane Wessels
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
 */

#ifndef SQUID_CLIENTSIDE_H
#define SQUID_CLIENTSIDE_H

#include "comm.h"
#include "HttpControlMsg.h"
#include "HttpParser.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_SSL
#include "ssl/support.h"
#endif

class ConnStateData;
class ClientHttpRequest;
class clientStreamNode;
class ChunkedCodingParser;
class HelperReply;
namespace AnyP
{
class PortCfg;
} // namespace Anyp

/**
 * Badly named.
 * This is in fact the processing context for a single HTTP request.
 *
 * Managing what has been done, and what happens next to the data buffer
 * holding what we hope is an HTTP request.
 *
 * Parsing is still a mess of global functions done in conjunction with the
 * real socket controller which generated ClientHttpRequest.
 * It also generates one of us and passes us control from there based on
 * the results of the parse.
 *
 * After that all the request interpretation and adaptation is in our scope.
 * Then finally the reply fetcher is created by this and we get the result
 * back. Which we then have to manage writing of it to the ConnStateData.
 *
 * The socket level management is done by a ConnStateData which owns us.
 * The scope of this objects control over a socket consists of the data
 * buffer received from ConnStateData with an initially unknown length.
 * When that length is known it sets the end bounary of our acces to the
 * buffer.
 *
 * The individual processing actions are done by other Jobs which we
 * kick off as needed.
 */
class ClientSocketContext : public RefCountable
{

public:
    typedef RefCount<ClientSocketContext> Pointer;
    ClientSocketContext();
    ~ClientSocketContext();
    bool startOfOutput() const;
    void writeComplete(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag);
    void keepaliveNextRequest();

    Comm::ConnectionPointer clientConnection; /// details about the client connection socket.
    ClientHttpRequest *http;	/* we own this */
    HttpReply *reply;
    char reqbuf[HTTP_REQBUF_SZ];
    Pointer next;

    struct {

        unsigned deferred:1; /* This is a pipelined request waiting for the current object to complete */

        unsigned parsed_ok:1; /* Was this parsed correctly? */
    } flags;
    bool mayUseConnection() const {return mayUseConnection_;}

    void mayUseConnection(bool aBool) {
        mayUseConnection_ = aBool;
        debugs(33,3, HERE << "This " << this << " marked " << aBool);
    }

    class DeferredParams
    {

    public:
        clientStreamNode *node;
        HttpReply *rep;
        StoreIOBuffer queuedBuffer;
    };

    DeferredParams deferredparams;
    int64_t writtenToSocket;
    void pullData();
    int64_t getNextRangeOffset() const;
    bool canPackMoreRanges() const;
    clientStream_status_t socketState();
    void sendBody(HttpReply * rep, StoreIOBuffer bodyData);
    void sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData);
    size_t lengthToSend(Range<int64_t> const &available);
    void noteSentBodyBytes(size_t);
    void buildRangeHeader(HttpReply * rep);
    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;
    void connIsFinished();
    void removeFromConnectionList(ConnStateData * conn);
    void deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData);
    bool multipartRangeRequest() const;
    void registerWithConn();
    void noteIoError(const int xerrno); ///< update state to reflect I/O error

    /// starts writing 1xx control message to the client
    void writeControlMsg(HttpControlMsg &msg);

protected:
    static IOCB WroteControlMsg;
    void wroteControlMsg(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag, int xerrno);

private:
    void prepareReply(HttpReply * rep);
    void packChunk(const StoreIOBuffer &bodyData, MemBuf &mb);
    void packRange(StoreIOBuffer const &, MemBuf * mb);
    void deRegisterWithConn();
    void doClose();
    void initiateClose(const char *reason);

    AsyncCall::Pointer cbControlMsgSent; ///< notifies HttpControlMsg Source

    bool mayUseConnection_; /* This request may use the connection. Don't read anymore requests for now */
    bool connRegistered_;

    CBDATA_CLASS2(ClientSocketContext);
};

class ConnectionDetail;
#if USE_SSL
namespace Ssl
{
class ServerBump;
}
#endif
/**
 * Manages a connection to a client.
 *
 * Multiple requests (up to pipeline_prefetch) can be pipelined. This object is responsible for managing
 * which one is currently being fulfilled and what happens to the queue if the current one
 * causes the client connection to be closed early.
 *
 * Act as a manager for the connection and passes data in buffer to the current parser.
 * the parser has ambiguous scope at present due to being made from global functions
 * I believe this object uses the parser to identify boundaries and kick off the
 * actual HTTP request handling objects (ClientSocketContext, ClientHttpRequest, HttpRequest)
 *
 * If the above can be confirmed accurate we can call this object PipelineManager or similar
 */
class ConnStateData : public BodyProducer, public HttpControlMsgSink
{

public:
    explicit ConnStateData(const MasterXaction::Pointer &xact);
    ~ConnStateData();

    void readSomeData();
    int getAvailableBufferLength() const;
    bool areAllContextsForThisConnection() const;
    void freeAllContexts();
    void notifyAllContexts(const int xerrno); ///< tell everybody about the err
    /// Traffic parsing
    bool clientParseRequests();
    void readNextRequest();
    bool maybeMakeSpaceAvailable();
    ClientSocketContext::Pointer getCurrentContext() const;
    void addContextToQueue(ClientSocketContext * context);
    int getConcurrentRequestCount() const;
    bool isOpen() const;
    void checkHeaderLimits();

    // HttpControlMsgSink API
    virtual void sendControlMsg(HttpControlMsg msg);

    // Client TCP connection details from comm layer.
    Comm::ConnectionPointer clientConnection;

    struct In {
        In();
        ~In();
        char *addressToReadInto() const;

        ChunkedCodingParser *bodyParser; ///< parses chunked request body
        char *buf;
        size_t notYetUsed;
        size_t allocatedSize;
    } in;

    /** number of body bytes we need to comm_read for the "current" request
     *
     * \retval 0         We do not need to read any [more] body bytes
     * \retval negative  May need more but do not know how many; could be zero!
     * \retval positive  Need to read exactly that many more body bytes
     */
    int64_t mayNeedToReadMoreBody() const;

#if USE_AUTH
    /**
     * Fetch the user details for connection based authentication
     * NOTE: this is ONLY connection based because NTLM and Negotiate is against HTTP spec.
     */
    const Auth::UserRequest::Pointer &getAuth() const { return auth_; }

    /**
     * Set the user details for connection-based authentication to use from now until connection closure.
     *
     * Any change to existing credentials shows that something invalid has happened. Such as:
     * - NTLM/Negotiate auth was violated by the per-request headers missing a revalidation token
     * - NTLM/Negotiate auth was violated by the per-request headers being for another user
     * - SSL-Bump CONNECT tunnel with persistent credentials has ended
     */
    void setAuth(const Auth::UserRequest::Pointer &aur, const char *cause);
#endif

    /**
     * used by the owner of the connection, opaque otherwise
     * TODO: generalise the connection owner concept.
     */
    ClientSocketContext::Pointer currentobject;

    Ip::Address log_addr;
    int nrequests;

    struct {
        bool readMore; ///< needs comm_read (for this request or new requests)
        bool swanSang; // XXX: temporary flag to check proper cleanup
    } flags;
    struct {
        Comm::ConnectionPointer serverConnection; /* pinned server side connection */
        char *host;             /* host name of pinned connection */
        int port;               /* port of pinned connection */
        bool pinned;             /* this connection was pinned */
        bool auth;               /* pinned for www authentication */
        bool zeroReply; ///< server closed w/o response (ERR_ZERO_SIZE_OBJECT)
        CachePeer *peer;             /* CachePeer the connection goes via */
        AsyncCall::Pointer readHandler; ///< detects serverConnection closure
        AsyncCall::Pointer closeHandler; /*The close handler for pinned server side connection*/
    } pinning;

    /// Squid listening port details where this connection arrived.
    AnyP::PortCfg *port;

    bool transparent() const;
    bool reading() const;
    void stopReading(); ///< cancels comm_read if it is scheduled

    /// true if we stopped receiving the request
    const char *stoppedReceiving() const { return stoppedReceiving_; }
    /// true if we stopped sending the response
    const char *stoppedSending() const { return stoppedSending_; }
    /// note request receiving error and close as soon as we write the response
    void stopReceiving(const char *error);
    /// note response sending error and close as soon as we read the request
    void stopSending(const char *error);

    void expectNoForwarding(); ///< cleans up virgin request [body] forwarding state

    BodyPipe::Pointer expectRequestBody(int64_t size);
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

    bool handleReadData(char *buf, size_t size);
    bool handleRequestBodyData();

    /**
     * Correlate the current ConnStateData object with the pinning_fd socket descriptor.
     */
    void pinConnection(const Comm::ConnectionPointer &pinServerConn, HttpRequest *request, CachePeer *peer, bool auth);
    /**
     * Decorrelate the ConnStateData object from its pinned CachePeer
     */
    void unpinConnection();
    /**
     * Checks if there is pinning info if it is valid. It can close the server side connection
     * if pinned info is not valid.
     \param request   if it is not NULL also checks if the pinning info refers to the request client side HttpRequest
     \param CachePeer      if it is not NULL also check if the CachePeer is the pinning CachePeer
     \return          The details of the server side connection (may be closed if failures were present).
     */
    const Comm::ConnectionPointer validatePinnedConnection(HttpRequest *request, const CachePeer *peer);
    /**
     * returts the pinned CachePeer if exists, NULL otherwise
     */
    CachePeer *pinnedPeer() const {return pinning.peer;}
    bool pinnedAuth() const {return pinning.auth;}

    // pining related comm callbacks
    void clientPinnedConnectionClosed(const CommCloseCbParams &io);

    // comm callbacks
    void clientReadRequest(const CommIoCbParams &io);
    void connStateClosed(const CommCloseCbParams &io);
    void requestTimeout(const CommTimeoutCbParams &params);

    // AsyncJob API
    virtual bool doneAll() const { return BodyProducer::doneAll() && false;}
    virtual void swanSong();

    /// Changes state so that we close the connection and quit after serving
    /// the client-side-detected error response instead of getting stuck.
    void quitAfterError(HttpRequest *request); // meant to be private

    /// The caller assumes responsibility for connection closure detection.
    void stopPinnedConnectionMonitoring();

#if USE_SSL
    /// called by FwdState when it is done bumping the server
    void httpsPeeked(Comm::ConnectionPointer serverConnection);

    /// Start to create dynamic SSL_CTX for host or uses static port SSL context.
    void getSslContextStart();
    /**
     * Done create dynamic ssl certificate.
     *
     * \param[in] isNew if generated certificate is new, so we need to add this certificate to storage.
     */
    void getSslContextDone(SSL_CTX * sslContext, bool isNew = false);
    /// Callback function. It is called when squid receive message from ssl_crtd.
    static void sslCrtdHandleReplyWrapper(void *data, const HelperReply &reply);
    /// Proccess response from ssl_crtd.
    void sslCrtdHandleReply(const HelperReply &reply);

    void switchToHttps(HttpRequest *request, Ssl::BumpMode bumpServerMode);
    bool switchedToHttps() const { return switchedToHttps_; }
    Ssl::ServerBump *serverBump() {return sslServerBump;}
    inline void setServerBump(Ssl::ServerBump *srvBump) {
        if (!sslServerBump)
            sslServerBump = srvBump;
        else
            assert(sslServerBump == srvBump);
    }
    /// Fill the certAdaptParams with the required data for certificate adaptation
    /// and create the key for storing/retrieve the certificate to/from the cache
    void buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties);
    /// Called when the client sends the first request on a bumped connection.
    /// Returns false if no [delayed] error should be written to the client.
    /// Otherwise, writes the error to the client and returns true. Also checks
    /// for SQUID_X509_V_ERR_DOMAIN_MISMATCH on bumped requests.
    bool serveDelayedError(ClientSocketContext *context);

    Ssl::BumpMode sslBumpMode; ///< ssl_bump decision (Ssl::bumpEnd if n/a).

#else
    bool switchedToHttps() const { return false; }
#endif

protected:
    void startDechunkingRequest();
    void finishDechunkingRequest(bool withSuccess);
    void abortChunkedRequestBody(const err_type error);
    err_type handleChunkedRequestBody(size_t &putSize);

    void startPinnedConnectionMonitoring();
    void clientPinnedConnectionRead(const CommIoCbParams &io);

private:
    int connReadWasError(comm_err_t flag, int size, int xerrno);
    int connFinishedWithConn(int size);
    void clientAfterReadingRequests();
    bool concurrentRequestQueueFilled() const;

#if USE_AUTH
    /// some user details that can be used to perform authentication on this connection
    Auth::UserRequest::Pointer auth_;
#endif

    HttpParser parser_;

    // XXX: CBDATA plays with public/private and leaves the following 'private' fields all public... :(

#if USE_SSL
    bool switchedToHttps_;
    /// The SSL server host name appears in CONNECT request or the server ip address for the intercepted requests
    String sslConnectHostOrIp; ///< The SSL server host name as passed in the CONNECT request
    String sslCommonName; ///< CN name for SSL certificate generation
    String sslBumpCertKey; ///< Key to use to store/retrieve generated certificate

    /// HTTPS server cert. fetching state for bump-ssl-server-first
    Ssl::ServerBump *sslServerBump;
    Ssl::CertSignAlgorithm signAlgorithm; ///< The signing algorithm to use
#endif

    /// the reason why we no longer write the response or nil
    const char *stoppedSending_;
    /// the reason why we no longer read the request or nil
    const char *stoppedReceiving_;

    AsyncCall::Pointer reader; ///< set when we are reading
    BodyPipe::Pointer bodyPipe; // set when we are reading request body

    CBDATA_CLASS2(ConnStateData);
};

void setLogUri(ClientHttpRequest * http, char const *uri, bool cleanUrl = false);

const char *findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end = NULL);

int varyEvaluateMatch(StoreEntry * entry, HttpRequest * req);

void clientOpenListenSockets(void);
void clientHttpConnectionsClose(void);
void httpRequestFree(void *);

#endif /* SQUID_CLIENTSIDE_H */
