
/*
 * $Id: http.h,v 1.26 2006/10/31 23:30:57 wessels Exp $
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
 */

#ifndef SQUID_HTTP_H
#define SQUID_HTTP_H

#include "StoreIOBuffer.h"
#include "comm.h"
#include "forward.h"
#include "Server.h"
#include "BodyReader.h"

#if ICAP_CLIENT
#include "ICAP/ICAPServiceRep.h"

class ICAPClientRespmodPrecache;

class ICAPAccessCheck;
#endif

class HttpStateData : public ServerStateData
{

public:
    HttpStateData(FwdState *);
    ~HttpStateData();

    static IOCB SendComplete;
    static IOCB SendRequestEntityWrapper;
    static IOCB ReadReplyWrapper;
    static CBCB RequestBodyHandlerWrapper;
    static void httpBuildRequestHeader(HttpRequest * request,
                                       HttpRequest * orig_request,
                                       StoreEntry * entry,
                                       HttpHeader * hdr_out,
                                       http_state_flags flags);
    /* should be private */
    void sendRequest();
    void processReplyHeader();
    void processReplyBody();
    void readReply(size_t len, comm_err_t flag, int xerrno);
    void maybeReadData();
    int cacheableReply();

#if ICAP_CLIENT
    virtual bool takeAdaptedHeaders(HttpReply *);
    virtual bool takeAdaptedBody(MemBuf *);
    virtual void finishAdapting(); // deletes icap
    virtual void abortAdapting();  // deletes icap
    virtual void icapSpaceAvailable();
#endif

    peer *_peer;		/* peer request made to */
    int eof;			/* reached end-of-object? */
    HttpRequest *orig_request;
    int fd;
    http_state_flags flags;
    off_t currentOffset;
    size_t read_sz;
    int body_bytes_read;	/* to find end of response, independent of StoreEntry */
    MemBuf *readBuf;
    bool ignoreCacheControl;
    bool surrogateNoStore;
    void processSurrogateControl(HttpReply *);
#if ICAP_CLIENT

    void icapAclCheckDone(ICAPServiceRep::Pointer);
    bool icapAccessCheckPending;
#endif

    /*
     * getReply() public only because it is called from a static function
     * as httpState->getReply()
     */
#if OLD
const HttpReply * getReply() const { return reply ? reply : entry->getReply(); }

#else
    const HttpReply * getReply() const { assert(reply); return reply; }

#endif

private:
    enum ConnectionStatus {
        INCOMPLETE_MSG,
        COMPLETE_PERSISTENT_MSG,
        COMPLETE_NONPERSISTENT_MSG
    };
    ConnectionStatus statusIfComplete() const;
    ConnectionStatus persistentConnStatus() const;
    void failReply (HttpReply *reply, http_status const &status);
    void keepaliveAccounting(HttpReply *);
    void checkDateSkew(HttpReply *);
    void haveParsedReplyHeaders();
    void transactionComplete();
    void writeReplyBody(const char *data, int len);
    void sendRequestEntityDone();
    void requestBodyHandler(MemBuf &);
    void sendRequestEntity(int fd, size_t size, comm_err_t errflag);
    mb_size_t buildRequestPrefix(HttpRequest * request,
                                 HttpRequest * orig_request,
                                 StoreEntry * entry,
                                 MemBuf * mb,
                                 http_state_flags flags);
    static bool decideIfWeDoRanges (HttpRequest * orig_request);

#if ICAP_CLIENT
    void backstabAdapter();
    void endAdapting();
#endif

private:
    CBDATA_CLASS2(HttpStateData);
};

#endif /* SQUID_HTTP_H */
