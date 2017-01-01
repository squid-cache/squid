/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "adaptation/Answer.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/Options.h"
#include "adaptation/icap/OptXact.h"
#include "base/TextException.h"
#include "comm.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, OptXact);
CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, OptXactLauncher);

Adaptation::Icap::OptXact::OptXact(Adaptation::Icap::ServiceRep::Pointer &aService):
    AsyncJob("Adaptation::Icap::OptXact"),
    Adaptation::Icap::Xaction("Adaptation::Icap::OptXact", aService),
    readAll(false)
{
}

void Adaptation::Icap::OptXact::start()
{
    Adaptation::Icap::Xaction::start();

    openConnection();
}

void Adaptation::Icap::OptXact::handleCommConnected()
{
    scheduleRead();

    MemBuf requestBuf;
    requestBuf.init();
    makeRequest(requestBuf);
    debugs(93, 9, HERE << "request " << status() << ":\n" <<
           (requestBuf.terminate(), requestBuf.content()));
    icap_tio_start = current_time;
    scheduleWrite(requestBuf);
}

void Adaptation::Icap::OptXact::makeRequest(MemBuf &buf)
{
    const Adaptation::Service &s = service();
    const String uri = s.cfg().uri;
    buf.appendf("OPTIONS " SQUIDSTRINGPH " ICAP/1.0\r\n", SQUIDSTRINGPRINT(uri));
    const String host = s.cfg().host;
    buf.appendf("Host: " SQUIDSTRINGPH ":%d\r\n", SQUIDSTRINGPRINT(host), s.cfg().port);

    if (!TheConfig.reuse_connections)
        buf.append("Connection: close\r\n", 19);

    if (TheConfig.allow206_enable)
        buf.append("Allow: 206\r\n", 12);
    buf.append(ICAP::crlf, 2);

    // XXX: HttpRequest cannot fully parse ICAP Request-Line
    Http::StatusCode reqStatus;
    buf.terminate(); // HttpMsg::parse requires terminated buffer
    Must(icapRequest->parse(buf.content(), buf.contentSize(), true, &reqStatus) > 0);
}

void Adaptation::Icap::OptXact::handleCommWrote(size_t size)
{
    debugs(93, 9, HERE << "finished writing " << size <<
           "-byte request " << status());
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::OptXact::handleCommRead(size_t)
{
    if (parseResponse()) {
        Must(icapReply != NULL);
        // We read everything if there is no response body. If there is a body,
        // we cannot parse it because we do not support any opt-body-types, so
        // we leave readAll false which forces connection closure.
        readAll = !icapReply->header.getByNameListMember("Encapsulated",
                  "opt-body", ',').size();
        debugs(93, 7, HERE << "readAll=" << readAll);
        icap_tio_finish = current_time;
        setOutcome(xoOpt);
        sendAnswer(Answer::Forward(icapReply.getRaw()));
        Must(done()); // there should be nothing else to do
        return;
    }

    scheduleRead();
}

bool Adaptation::Icap::OptXact::parseResponse()
{
    debugs(93, 5, "have " << readBuf.length() << " bytes to parse" << status());
    debugs(93, DBG_DATA, "\n" << readBuf);

    HttpReply::Pointer r(new HttpReply);
    r->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    if (!parseHttpMsg(r.getRaw())) // throws on errors
        return false;

    if (httpHeaderHasConnDir(&r->header, "close"))
        reuseConnection = false;

    icapReply = r;
    return true;
}

void Adaptation::Icap::OptXact::swanSong()
{
    Adaptation::Icap::Xaction::swanSong();
}

void Adaptation::Icap::OptXact::finalizeLogInfo()
{
    //    al.cache.caddr = 0;
    al.icap.reqMethod = Adaptation::methodOptions;

    if (icapReply != NULL && al.icap.bytesRead > icapReply->hdr_sz)
        al.icap.bodyBytesRead = al.icap.bytesRead - icapReply->hdr_sz;

    Adaptation::Icap::Xaction::finalizeLogInfo();
}

/* Adaptation::Icap::OptXactLauncher */

Adaptation::Icap::OptXactLauncher::OptXactLauncher(Adaptation::ServicePointer aService):
    AsyncJob("Adaptation::Icap::OptXactLauncher"),
    Adaptation::Icap::Launcher("Adaptation::Icap::OptXactLauncher", aService)
{
}

Adaptation::Icap::Xaction *Adaptation::Icap::OptXactLauncher::createXaction()
{
    Adaptation::Icap::ServiceRep::Pointer s =
        dynamic_cast<Adaptation::Icap::ServiceRep*>(theService.getRaw());
    Must(s != NULL);
    return new Adaptation::Icap::OptXact(s);
}

