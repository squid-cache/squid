
/*
 * $Id: client_side.h,v 1.1 2003/03/04 02:57:50 robertc Exp $
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

class ConnStateData
{

public:
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
    void *currentobject;	/* used by the owner of the connection. Opaque otherwise */

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
};

#endif /* SQUID_CLIENTSIDE_H */
