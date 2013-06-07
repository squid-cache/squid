
/*
 * DEBUG: section 75    WHOIS protocol
 * AUTHOR: Duane Wessels, Kostas Anagnostakis
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

#include "squid.h"
#include "comm.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "FwdState.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

#define WHOIS_PORT 43

class WhoisState
{

public:
    ~WhoisState();
    void readReply(const Comm::ConnectionPointer &, char *aBuffer, size_t aBufferLength, comm_err_t flag, int xerrno);
    void setReplyToOK(StoreEntry *sentry);
    StoreEntry *entry;
    HttpRequest *request;
    FwdState::Pointer fwd;
    char buf[BUFSIZ+1];		/* readReply adds terminating NULL */
    bool dataWritten;
};

static CLCB whoisClose;
static CTCB whoisTimeout;
static IOCB whoisReadReply;

/* PUBLIC */

CBDATA_TYPE(WhoisState);

WhoisState::~WhoisState()
{
    fwd = NULL;	// refcounted
}

static void
whoisWriteComplete(const Comm::ConnectionPointer &, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    xfree(buf);
}

void
whoisStart(FwdState * fwd)
{
    WhoisState *p;
    char *buf;
    size_t l;
    CBDATA_INIT_TYPE(WhoisState);
    p = cbdataAlloc(WhoisState);
    p->request = fwd->request;
    p->entry = fwd->entry;
    p->fwd = fwd;
    p->dataWritten = false;

    p->entry->lock();
    comm_add_close_handler(fwd->serverConnection()->fd, whoisClose, p);

    l = p->request->urlpath.size() + 3;

    buf = (char *)xmalloc(l);

    String str_print=p->request->urlpath.substr(1,p->request->urlpath.size());
    snprintf(buf, l, SQUIDSTRINGPH"\r\n", SQUIDSTRINGPRINT(str_print));

    AsyncCall::Pointer writeCall = commCbCall(5,5, "whoisWriteComplete",
                                   CommIoCbPtrFun(whoisWriteComplete, p));
    Comm::Write(fwd->serverConnection(), buf, strlen(buf), writeCall, NULL);
    AsyncCall::Pointer readCall = commCbCall(5,4, "whoisReadReply",
                                  CommIoCbPtrFun(whoisReadReply, p));
    comm_read(fwd->serverConnection(), p->buf, BUFSIZ, readCall);
    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "whoisTimeout",
                                     CommTimeoutCbPtrFun(whoisTimeout, p));
    commSetConnTimeout(fwd->serverConnection(), Config.Timeout.read, timeoutCall);
}

/* PRIVATE */

static void
whoisTimeout(const CommTimeoutCbParams &io)
{
    WhoisState *p = static_cast<WhoisState *>(io.data);
    debugs(75, 3, HERE << io.conn << ", URL " << p->entry->url());
    io.conn->close();
}

static void
whoisReadReply(const Comm::ConnectionPointer &conn, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    WhoisState *p = (WhoisState *)data;
    p->readReply(conn, buf, len, flag, xerrno);
}

void
WhoisState::setReplyToOK(StoreEntry *sentry)
{
    HttpReply *reply = new HttpReply;
    sentry->buffer();
    reply->setHeaders(Http::scOkay, "Gatewaying", "text/plain", -1, -1, -2);
    sentry->replaceHttpReply(reply);
}

void
WhoisState::readReply(const Comm::ConnectionPointer &conn, char *aBuffer, size_t aBufferLength, comm_err_t flag, int xerrno)
{
    /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */
    if (flag == COMM_ERR_CLOSING)
        return;

    aBuffer[aBufferLength] = '\0';
    debugs(75, 3, HERE << conn << " read " << aBufferLength << " bytes");
    debugs(75, 5, "{" << aBuffer << "}");

    if (flag != COMM_OK) {
        debugs(50, 2, HERE  << conn << ": read failure: " << xstrerror() << ".");

        if (ignoreErrno(errno)) {
            AsyncCall::Pointer call = commCbCall(5,4, "whoisReadReply",
                                                 CommIoCbPtrFun(whoisReadReply, this));
            comm_read(conn, aBuffer, BUFSIZ, call);
        } else {
            ErrorState *err = new ErrorState(ERR_READ_ERROR, Http::scInternalServerError, fwd->request);
            err->xerrno = xerrno;
            fwd->fail(err);
            conn->close();
        }
        return;
    }

    if (aBufferLength > 0) {
        if (!dataWritten)
            setReplyToOK(entry);

        kb_incr(&(statCounter.server.all.kbytes_in), aBufferLength);
        kb_incr(&(statCounter.server.http.kbytes_in), aBufferLength);

        /* No range support, we always grab it all */
        dataWritten = true;
        entry->append(aBuffer, aBufferLength);
        entry->flush();

        AsyncCall::Pointer call = commCbCall(5,4, "whoisReadReply",
                                             CommIoCbPtrFun(whoisReadReply, this));
        comm_read(conn, aBuffer, BUFSIZ, call);
        return;
    }

    /* no bytes read. stop reading */
    entry->timestampsSet();
    entry->flush();

    if (!EBIT_TEST(entry->flags, RELEASE_REQUEST))
        entry->setPublicKey();

    fwd->complete();
    debugs(75, 3, "whoisReadReply: Done: " << entry->url());
    conn->close();
}

static void
whoisClose(const CommCloseCbParams &params)
{
    WhoisState *p = (WhoisState *)params.data;
    debugs(75, 3, "whoisClose: FD " << params.fd);
    p->entry->unlock();
    cbdataFree(p);
}
