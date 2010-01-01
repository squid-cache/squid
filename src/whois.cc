
/*
 * $Id$
 *
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
#include "errorpage.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "comm.h"
#include "HttpRequest.h"
#include "forward.h"

#define WHOIS_PORT 43

class WhoisState
{

public:
    ~WhoisState();
    void readReply (int fd, char *aBuffer, size_t aBufferLength, comm_err_t flag, int xerrno);
    void setReplyToOK(StoreEntry *sentry);
    StoreEntry *entry;
    HttpRequest *request;
    FwdState::Pointer fwd;
    char buf[BUFSIZ+1];		/* readReply adds terminating NULL */
    bool dataWritten;
};

static PF whoisClose;
static PF whoisTimeout;
static IOCB whoisReadReply;

/* PUBLIC */

CBDATA_TYPE(WhoisState);

WhoisState::~WhoisState()
{
    fwd = NULL;	// refcounted
}

static void
whoisWriteComplete(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    xfree(buf);
}

void
whoisStart(FwdState * fwd)
{
    WhoisState *p;
    int fd = fwd->server_fd;
    char *buf;
    size_t l;
    CBDATA_INIT_TYPE(WhoisState);
    p = cbdataAlloc(WhoisState);
    p->request = fwd->request;
    p->entry = fwd->entry;
    p->fwd = fwd;
    p->dataWritten = false;

    p->entry->lock();
    comm_add_close_handler(fd, whoisClose, p);

    l = p->request->urlpath.size() + 3;

    buf = (char *)xmalloc(l);

    String str_print=p->request->urlpath.substr(1,p->request->urlpath.size());
    snprintf(buf, l, SQUIDSTRINGPH"\r\n", SQUIDSTRINGPRINT(str_print));

    comm_write(fd, buf, strlen(buf), whoisWriteComplete, p, NULL);
    comm_read(fd, p->buf, BUFSIZ, whoisReadReply, p);
    commSetTimeout(fd, Config.Timeout.read, whoisTimeout, p);
}

/* PRIVATE */

static void
whoisTimeout(int fd, void *data)
{
    WhoisState *p = (WhoisState *)data;
    debugs(75, 1, "whoisTimeout: " << p->entry->url()  );
    whoisClose(fd, p);
}

static void
whoisReadReply(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    WhoisState *p = (WhoisState *)data;
    p->readReply(fd, buf, len, flag, xerrno);
}

void
WhoisState::setReplyToOK(StoreEntry *sentry)
{
    HttpReply *reply = new HttpReply;
    sentry->buffer();
    HttpVersion version(1, 0);
    reply->setHeaders(version, HTTP_OK, "Gatewaying", "text/plain", -1, -1, -2);
    sentry->replaceHttpReply(reply);
}

void
WhoisState::readReply (int fd, char *aBuffer, size_t aBufferLength, comm_err_t flag, int xerrno)
{
    int do_next_read = 0;

    /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */

    if (flag == COMM_ERR_CLOSING) {
        return;
    }

    aBuffer[aBufferLength] = '\0';
    debugs(75, 3, "whoisReadReply: FD " << fd << " read " << aBufferLength << " bytes");
    debugs(75, 5, "{" << aBuffer << "}");

    if (flag == COMM_OK && aBufferLength > 0) {
        if (!dataWritten)
            setReplyToOK(entry);

        kb_incr(&statCounter.server.all.kbytes_in, aBufferLength);

        kb_incr(&statCounter.server.http.kbytes_in, aBufferLength);

        /* No range support, we always grab it all */
        dataWritten = true;

        entry->append(aBuffer, aBufferLength);

        entry->flush();

        do_next_read = 1;
    } else if (flag != COMM_OK || aBufferLength < 0) {
        debugs(50, 2, "whoisReadReply: FD " << fd << ": read failure: " << xstrerror() << ".");

        if (ignoreErrno(errno)) {
            do_next_read = 1;
        } else {
            ErrorState *err;
            err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR, fwd->request);
            err->xerrno = errno;
            fwd->fail(err);
            comm_close(fd);
            do_next_read = 0;
        }
    } else {
        entry->timestampsSet();
        entry->flush();

        if (!EBIT_TEST(entry->flags, RELEASE_REQUEST))
            entry->setPublicKey();

        fwd->complete();

        debugs(75, 3, "whoisReadReply: Done: " << entry->url()  );

        comm_close(fd);

        do_next_read = 0;
    }

    if (do_next_read)
        comm_read(fd, aBuffer, BUFSIZ, whoisReadReply, this);
}

static void
whoisClose(int fd, void *data)
{
    WhoisState *p = (WhoisState *)data;
    debugs(75, 3, "whoisClose: FD " << fd);
    p->entry->unlock();
    cbdataFree(p);
}
