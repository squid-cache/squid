
/*
 * $Id: client_side.h,v 1.4 2003/07/11 02:11:47 robertc Exp $
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

#include "StoreIOBuffer.h"
#include "RefCount.h"

class ConnStateData;

class ClientHttpRequest;

class clientStreamNode;

class ClientSocketContext : public RefCountable
{

public:
    typedef RefCount<ClientSocketContext> Pointer;
    void *operator new(size_t);
    void operator delete(void *);
    void deleteSelf() const;
    ClientSocketContext();
    ~ClientSocketContext();
    bool startOfOutput() const;
    void writeComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag);
    void keepaliveNextRequest();
    ClientHttpRequest *http;	/* we own this */
    char reqbuf[HTTP_REQBUF_SZ];
    Pointer next;

    struct
    {

int deferred:
        1; /* This is a pipelined request waiting for the current object to complete */

int parsed_ok:
        1; /* Was this parsed correctly? */
    }

    flags;
    bool mayUseConnection() const {return mayUseConnection_;}

    void mayUseConnection(bool aBool)
    {
        mayUseConnection_ = aBool;
        debug (33,3)("ClientSocketContext::mayUseConnection: This %p marked %d\n",
                     this, aBool);
    }

    struct
    {
        clientStreamNode *node;
        HttpReply *rep;
        StoreIOBuffer queuedBuffer;
    }

    deferredparams;
    off_t writtenToSocket;
    void pullData();
    off_t getNextRangeOffset() const;
    bool canPackMoreRanges() const;
    clientStream_status_t socketState();
    void sendBody(HttpReply * rep, StoreIOBuffer bodyData);
    void sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData);
    size_t lengthToSend(size_t maximum);
    void noteSentBodyBytes(size_t);
    void buildRangeHeader(HttpReply * rep);
    int fd() const;
    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;
    void connIsFinished();
    void removeFromConnectionList(RefCount<ConnStateData> conn);
    void deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer recievedData);
    bool multipartRangeRequest() const;
    void packRange(const char **buf,
                   size_t size,
                   MemBuf * mb);
    void registerWithConn();

private:
    CBDATA_CLASS(ClientSocketContext);
    void prepareReply(HttpReply * rep);
    void deRegisterWithConn();
    bool mayUseConnection_; /* This request may use the connection. Don't read anymore requests for now */
    bool connRegistered_;
};

class ConnStateData : public RefCountable
{

public:
    typedef RefCount<ConnStateData> Pointer;
    void * operator new (size_t);
    void operator delete (void *);
    void deleteSelf() const;

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
    }

    in;

    struct
    {
        size_t size_left;	/* How much body left to process */
        request_t *request;	/* Parameters passed to clientReadBody */
        char *buf;
        size_t bufsize;
        CBCB *callback;
        void *cbdata;
    }

    body;
    auth_type_t auth_type;	/* Is this connection based authentication? if so what type it is. */
    /* note this is ONLY connection based because NTLM is against HTTP spec */
    /* the user details for connection based authentication */
    auth_user_request_t *auth_user_request;
    /* TODO: generalise the connection owner concept */
    ClientSocketContext::Pointer currentobject;	/* used by the owner of the connection. Opaque otherwise */

    struct sockaddr_in peer;

    struct sockaddr_in me;

    struct in_addr log_addr;
    char rfc931[USER_IDENT_SZ];
    int nrequests;

    struct
    {

int readMoreRequests:
        1;
    }

    flags;
    http_port_list *port;

    bool transparent() const;
    void transparent(bool const);
    bool reading() const;
    void reading(bool const);

private:
    CBDATA_CLASS(ConnStateData);
    bool transparent_;
    bool reading_;
    Pointer openReference;
};

#endif /* SQUID_CLIENTSIDE_H */
