/*
 * $Id: client_side.h,v 1.26.2.1 2008/02/25 23:08:50 amosjeffries Exp $
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

#ifndef SQUID_CLIENTSIDE_H
#define SQUID_CLIENTSIDE_H

#include "comm.h"
#include "StoreIOBuffer.h"
#include "BodyPipe.h"
#include "RefCount.h"

class ConnStateData;

class ClientHttpRequest;

class clientStreamNode;

class AuthUserRequest;

template <class T>

class Range;

class ClientSocketContext : public RefCountable
{

public:
    typedef RefCount<ClientSocketContext> Pointer;
    void *operator new(size_t);
    void operator delete(void *);
    ClientSocketContext();
    ~ClientSocketContext();
    bool startOfOutput() const;
    void writeComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag);
    void keepaliveNextRequest();
    ClientHttpRequest *http;	/* we own this */
    HttpReply *reply;
    char reqbuf[HTTP_REQBUF_SZ];
    Pointer next;

    struct
    {

unsigned deferred: 1; /* This is a pipelined request waiting for the current object to complete */

unsigned parsed_ok: 1; /* Was this parsed correctly? */
    }

    flags;
    bool mayUseConnection() const {return mayUseConnection_;}

    void mayUseConnection(bool aBool)
    {
        mayUseConnection_ = aBool;
        debug (33,3)("ClientSocketContext::mayUseConnection: This %p marked %d\n",
                     this, aBool);
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
    int fd() const;
    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;
    void connIsFinished();
    void removeFromConnectionList(RefCount<ConnStateData> conn);
    void deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData);
    bool multipartRangeRequest() const;
    void registerWithConn();

private:
    CBDATA_CLASS(ClientSocketContext);
    void prepareReply(HttpReply * rep);
    void packRange(StoreIOBuffer const &, MemBuf * mb);
    void deRegisterWithConn();
    void doClose();
    void initiateClose(const char *reason);
    bool mayUseConnection_; /* This request may use the connection. Don't read anymore requests for now */
    bool connRegistered_;
};

/* A connection to a socket */
class ConnStateData : public BodyProducer, public RefCountable
{

public:
    typedef RefCount<ConnStateData> Pointer;

    ConnStateData();
    ~ConnStateData();

    void readSomeData();
    int getAvailableBufferLength() const;
    bool areAllContextsForThisConnection() const;
    void freeAllContexts();
    void readNextRequest();
    void makeSpaceAvailable();
    ClientSocketContext::Pointer getCurrentContext() const;
    void addContextToQueue(ClientSocketContext * context);
    int getConcurrentRequestCount() const;
    void close();
    bool isOpen() const;

    int fd;

    struct In
    {
        In();
        ~In();
        char *addressToReadInto() const;
        char *buf;
        size_t notYetUsed;
        size_t allocatedSize;
    } in;

    int64_t bodySizeLeft();

    /*
     * Is this connection based authentication? if so what type it
     * is.
     */
    auth_type_t auth_type;
    /*
     * note this is ONLY connection based because NTLM is against HTTP spec.
     * the user details for connection based authentication
     */
    AuthUserRequest *auth_user_request;
    /*
     * used by the owner of the connection, opaque otherwise
     * TODO: generalise the connection owner concept.
     */
    ClientSocketContext::Pointer currentobject;

    struct sockaddr_in peer;

    struct sockaddr_in me;

    struct IN_ADDR log_addr;
    char rfc931[USER_IDENT_SZ];
    int nrequests;

    struct
    {
        bool readMoreRequests;
    }

    flags;
    http_port_list *port;

    bool transparent() const;
    void transparent(bool const);
    bool reading() const;
    void reading(bool const);

    bool closing() const;
    void startClosing(const char *reason);

    BodyPipe::Pointer expectRequestBody(int64_t size);
    virtual void noteMoreBodySpaceAvailable(BodyPipe &);
    virtual void noteBodyConsumerAborted(BodyPipe &);

    void handleReadData(char *buf, size_t size);
    void handleRequestBodyData();

private:
    CBDATA_CLASS2(ConnStateData);
    bool transparent_;
    bool reading_;
    bool closing_;
    Pointer openReference;
    BodyPipe::Pointer bodyPipe; // set when we are reading request body
};

/* convenience class while splitting up body handling */
/* temporary existence only - on stack use expected */

void setLogUri(ClientHttpRequest * http, char const *uri);

const char *findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end = NULL);

#endif /* SQUID_CLIENTSIDE_H */
