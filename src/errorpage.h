
/*
 * $Id: errorpage.h,v 1.2 2006/08/25 15:22:34 serassio Exp $
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_ERRORPAGE_H
#define   SQUID_ERRORPAGE_H

#include "squid.h"
#include "cbdata.h"

class ErrorState
{

public:
    err_type type;
    int page_id;
    http_status httpStatus;
    auth_user_request_t *auth_user_request;
    HttpRequest *request;
    char *url;
    int xerrno;
    u_short port;
    char *dnsserver_msg;
    time_t ttl;

    struct IN_ADDR src_addr;
    char *redirect_url;
    ERCB *callback;
    void *callback_data;

    struct
    {

unsigned int flag_cbdata:
        1;
    }

    flags;

    struct
    {
        wordlist *server_msg;
        char *request;
        char *reply;
    }

    ftp;
    char *request_hdrs;
    char *err_msg; /* Preformatted error message from the cache */

private:
    CBDATA_CLASS2(ErrorState);
};

SQUIDCEXTERN void errorInitialize(void);
SQUIDCEXTERN void errorClean(void);
SQUIDCEXTERN HttpReply *errorBuildReply(ErrorState * err);
SQUIDCEXTERN void errorSend(int fd, ErrorState *);
SQUIDCEXTERN void errorAppendEntry(StoreEntry *, ErrorState *);
SQUIDCEXTERN void errorStateFree(ErrorState * err);
SQUIDCEXTERN err_type errorReservePageId(const char *page_name);
SQUIDCEXTERN ErrorState *errorCon(err_type type, http_status, HttpRequest * request);


#endif /* SQUID_ERRORPAGE_H */
