
/*
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

#ifndef SQUID_HTTP_H
#define SQUID_HTTP_H

#include "comm.h"
#include "HttpStateFlags.h"
#include "Server.h"

class ChunkedCodingParser;
class FwdState;
class HttpHeader;

class HttpStateData : public ServerStateData
{

public:
    HttpStateData(FwdState *);
    ~HttpStateData();

    static void httpBuildRequestHeader(HttpRequest * request,
                                       StoreEntry * entry,
                                       const AccessLogEntryPointer &al,
                                       HttpHeader * hdr_out,
                                       const HttpStateFlags &flags);

    virtual const Comm::ConnectionPointer & dataConnection() const;
    /* should be private */
    bool sendRequest();
    void processReplyHeader();
    void processReplyBody();
    void readReply(const CommIoCbParams &io);
    virtual void maybeReadVirginBody(); // read response data from the network

    // Determine whether the response is a cacheable representation
    int cacheableReply();

    CachePeer *_peer;		/* CachePeer request made to */
    int eof;			/* reached end-of-object? */
    int lastChunk;		/* reached last chunk of a chunk-encoded reply */
    HttpStateFlags flags;
    size_t read_sz;
    int header_bytes_read;	// to find end of response,
    int64_t reply_bytes_read;	// without relying on StoreEntry
    int body_bytes_truncated; // positive when we read more than we wanted
    MemBuf *readBuf;
    bool ignoreCacheControl;
    bool surrogateNoStore;

    void processSurrogateControl(HttpReply *);

protected:
    void processReply();
    void proceedAfter1xx();
    void handle1xx(HttpReply *msg);

private:
    /**
     * The current server connection.
     * Maybe open, closed, or NULL.
     * Use doneWithServer() to check if the server is available for use.
     */
    Comm::ConnectionPointer serverConnection;
    AsyncCall::Pointer closeHandler;
    enum ConnectionStatus {
        INCOMPLETE_MSG,
        COMPLETE_PERSISTENT_MSG,
        COMPLETE_NONPERSISTENT_MSG
    };
    ConnectionStatus statusIfComplete() const;
    ConnectionStatus persistentConnStatus() const;
    void keepaliveAccounting(HttpReply *);
    void checkDateSkew(HttpReply *);

    bool continueAfterParsingHeader();
    void truncateVirginBody();

    virtual void start();
    virtual void haveParsedReplyHeaders();
    virtual bool getMoreRequestBody(MemBuf &buf);
    virtual void closeServer(); // end communication with the server
    virtual bool doneWithServer() const; // did we end communication?
    virtual void abortTransaction(const char *reason); // abnormal termination

    // consuming request body
    virtual void handleMoreRequestBodyAvailable();
    virtual void handleRequestBodyProducerAborted();

    void writeReplyBody();
    bool decodeAndWriteReplyBody();
    bool finishingBrokenPost();
    bool finishingChunkedRequest();
    void doneSendingRequestBody();
    void requestBodyHandler(MemBuf &);
    virtual void sentRequestBody(const CommIoCbParams &io);
    void wroteLast(const CommIoCbParams &io);
    void sendComplete();
    void httpStateConnClosed(const CommCloseCbParams &params);
    void httpTimeout(const CommTimeoutCbParams &params);

    mb_size_t buildRequestPrefix(MemBuf * mb);
    static bool decideIfWeDoRanges (HttpRequest * orig_request);
    bool peerSupportsConnectionPinning() const;

    ChunkedCodingParser *httpChunkDecoder;
private:
    CBDATA_CLASS2(HttpStateData);
};

int httpCachable(const HttpRequestMethod&);
void httpStart(FwdState *);
const char *httpMakeVaryMark(HttpRequest * request, HttpReply const * reply);

#endif /* SQUID_HTTP_H */
