/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 75    WHOIS protocol */

#include "squid.h"
#include "comm.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "FwdState.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"

#include <cerrno>

class WhoisState
{
    CBDATA_CLASS(WhoisState);

public:
    void readReply(const Comm::ConnectionPointer &, char *aBuffer, size_t aBufferLength, Comm::Flag flag, int xerrno);
    void setReplyToOK(StoreEntry *sentry);
    StoreEntry *entry;
    HttpRequest::Pointer request;
    FwdState::Pointer fwd;
    char buf[BUFSIZ+1];     /* readReply adds terminating NULL */
    bool dataWritten;
};

CBDATA_CLASS_INIT(WhoisState);

static CLCB whoisClose;
static CTCB whoisTimeout;
static IOCB whoisReadReply;

/* PUBLIC */

static void
whoisWriteComplete(const Comm::ConnectionPointer &, char *buf, size_t, Comm::Flag, int, void *)
{
    xfree(buf);
}

void
whoisStart(FwdState * fwd)
{
    WhoisState *p = new WhoisState;
    p->request = fwd->request;
    p->entry = fwd->entry;
    p->fwd = fwd;
    p->dataWritten = false;

    p->entry->lock("whoisStart");
    comm_add_close_handler(fwd->serverConnection()->fd, whoisClose, p);

    size_t l = p->request->url.path().length() + 3;
    char *buf = (char *)xmalloc(l);

    const SBuf str_print = p->request->url.path().substr(1);
    snprintf(buf, l, SQUIDSBUFPH "\r\n", SQUIDSBUFPRINT(str_print));

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
whoisReadReply(const Comm::ConnectionPointer &conn, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data)
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
    reply->sources |= Http::Message::srcWhois;
    sentry->replaceHttpReply(reply);
}

void
WhoisState::readReply(const Comm::ConnectionPointer &conn, char *aBuffer, size_t aBufferLength, Comm::Flag flag, int xerrno)
{
    /* Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us */
    if (flag == Comm::ERR_CLOSING)
        return;

    aBuffer[aBufferLength] = '\0';
    debugs(75, 3, HERE << conn << " read " << aBufferLength << " bytes");
    debugs(75, 5, "{" << aBuffer << "}");

    // TODO: Honor delay pools.

    // XXX: Update statCounter before bailing
    if (!entry->isAccepting()) {
        debugs(52, 3, "terminating due to bad " << *entry);
        // TODO: Do not abuse connection for triggering cleanup.
        conn->close();
        return;
    }

    if (flag != Comm::OK) {
        debugs(50, 2, conn << ": read failure: " << xstrerr(xerrno));

        if (ignoreErrno(xerrno)) {
            AsyncCall::Pointer call = commCbCall(5,4, "whoisReadReply",
                                                 CommIoCbPtrFun(whoisReadReply, this));
            comm_read(conn, aBuffer, BUFSIZ, call);
        } else {
            const auto err = new ErrorState(ERR_READ_ERROR, Http::scInternalServerError, fwd->request, fwd->al);
            err->xerrno = xerrno;
            fwd->fail(err);
            conn->close();
        }
        return;
    }

    if (aBufferLength > 0) {
        if (!dataWritten)
            setReplyToOK(entry);

        statCounter.server.all.kbytes_in += aBufferLength;
        statCounter.server.http.kbytes_in += aBufferLength;

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

    if (!entry->makePublic())
        entry->makePrivate(true);

    if (dataWritten) // treat zero-length responses as incomplete
        fwd->markStoredReplyAsWhole("whois received/stored the entire response");

    fwd->complete();
    debugs(75, 3, "whoisReadReply: Done: " << entry->url());
    conn->close();
}

static void
whoisClose(const CommCloseCbParams &params)
{
    WhoisState *p = (WhoisState *)params.data;
    debugs(75, 3, "whoisClose: FD " << params.fd);
    // We do not own a Connection. Assume that FwdState is also monitoring.
    p->entry->unlock("whoisClose");
    delete p;
}

