
/*
 * $Id: client_side_request.h,v 1.2 2003/01/23 00:37:18 robertc Exp $
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

#ifndef SQUID_CLIENTSIDEREQUEST_H
#define SQUID_CLIENTSIDEREQUEST_H

#include "HttpHeader.h"
#include "clientStream.h"

/* client_side_request.c - client side request related routines (pure logic) */
extern int clientBeginRequest(method_t, char const *, CSCB *, CSD *, void *, HttpHeader const *, char *, size_t);

typedef class ClientHttpRequest clientHttpRequest;

class ClientHttpRequest {
public:
    void *operator new (size_t);
    void operator delete (void *);
    void deleteSelf() const;

    ClientHttpRequest();
    ~ClientHttpRequest();
    /* Not implemented - present to prevent synthetic operations */
    ClientHttpRequest(ClientHttpRequest const &);
    ClientHttpRequest& operator=(ClientHttpRequest const &);
    
    String rangeBoundaryStr() const;
    void freeResources();
    void updateCounters();
    void logRequest();
    MemObject * memObject() const;
    bool multipartRangeRequest() const;
    ConnStateData *conn;
    request_t *request;		/* Parsed URL ... */
    char *uri;
    char *log_uri;
    struct {
	off_t offset;
	size_t size;
	size_t headers_sz;
    } out;
    HttpHdrRangeIter range_iter;	/* data for iterating thru range specs */
    size_t req_sz;		/* raw request size on input, not current request size */
    StoreEntry *entry;
    StoreEntry *old_entry;
    log_type logType;
    struct timeval start;
    http_version_t http_ver;
    AccessLogEntry al;
    struct {
	unsigned int accel:1;
	unsigned int internal:1;
	unsigned int done_copying:1;
	unsigned int purging:1;
    } flags;
    struct {
	http_status status;
	char *location;
    } redirect;
    dlink_node active;
    dlink_list client_stream;
    int mRangeCLen();
private:
    CBDATA_CLASS(ClientHttpRequest);
};

/* client http based routines */
SQUIDCEXTERN char *clientConstructTraceEcho(clientHttpRequest *);
SQUIDCEXTERN aclCheck_t *clientAclChecklistCreate(const acl_access * acl, const clientHttpRequest * http);
SQUIDCEXTERN void *clientReplyNewContext(clientHttpRequest *);
SQUIDCEXTERN int clientHttpRequestStatus(int fd, clientHttpRequest const *http);

/* ones that should be elsewhere */
SQUIDCEXTERN void redirectStart(clientHttpRequest *, RH *, void *);

SQUIDCEXTERN void sslStart(clientHttpRequest *, size_t *, int *);

#if DELAY_POOLS
SQUIDCEXTERN delay_id delayClient(clientHttpRequest *);
#endif

#endif /* SQUID_CLIENTSIDEREQUEST_H */
