
/*
 * $Id$
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

#ifndef SQUID_ICAPXACTION_H
#define SQUID_ICAPXACTION_H

#include "comm.h"
#include "CommCalls.h"
#include "MemBuf.h"
#include "adaptation/icap/ServiceRep.h"
#include "adaptation/Initiate.h"
#include "AccessLogEntry.h"
#include "HttpReply.h"

class CommConnectCbParams;

namespace Adaptation
{
namespace Icap
{

/*
 * The ICAP Xaction implements common tasks for ICAP OPTIONS, REQMOD, and
 * RESPMOD transactions. It is started by an Initiator. It terminates
 * on its own, when done. Transactions communicate with Initiator using
 * asynchronous messages because a transaction or Initiator may be gone at
 * any time.
 */

// Note: Xaction must be the first parent for object-unaware cbdata to work

class Xaction: public Adaptation::Initiate
{

public:
    Xaction(const char *aTypeName, ServiceRep::Pointer &aService);
    virtual ~Xaction();

    void disableRetries();
    void disableRepeats(const char *reason);
    bool retriable() const { return isRetriable; }
    bool repeatable() const { return isRepeatable; }

    // comm handler wrappers, treat as private
    void noteCommConnected(const CommConnectCbParams &io);
    void noteCommWrote(const CommIoCbParams &io);
    void noteCommRead(const CommIoCbParams &io);
    void noteCommTimedout(const CommTimeoutCbParams &io);
    void noteCommClosed(const CommCloseCbParams &io);

    // TODO: create these only when actually sending/receiving
    HttpRequest *icapRequest; ///< sent (or at least created) ICAP request
    HttpReply::Pointer icapReply; ///< received ICAP reply, if any

    /// the number of times we tried to get to the service, including this time
    int attempts;

protected:
    virtual void start();
    virtual void noteInitiatorAborted(); // TODO: move to Adaptation::Initiate

    // comm hanndlers; called by comm handler wrappers
    virtual void handleCommConnected() = 0;
    virtual void handleCommWrote(size_t sz) = 0;
    virtual void handleCommRead(size_t sz) = 0;
    virtual void handleCommTimedout();
    virtual void handleCommClosed();

    void openConnection();
    void closeConnection();
    void dieOnConnectionFailure();

    void scheduleRead();
    void scheduleWrite(MemBuf &buf);
    void updateTimeout();

    void cancelRead();

    bool parseHttpMsg(HttpMsg *msg); // true=success; false=needMore; throw=err
    bool mayReadMore() const;

    virtual bool doneReading() const;
    virtual bool doneWriting() const;
    bool doneWithIo() const;
    virtual bool doneAll() const;

    // called just before the 'done' transaction is deleted
    virtual void swanSong();

    // returns a temporary string depicting transaction status, for debugging
    virtual const char *status() const;
    virtual void fillPendingStatus(MemBuf &buf) const;
    virtual void fillDoneStatus(MemBuf &buf) const;

    // useful for debugging
    virtual bool fillVirginHttpHeader(MemBuf&) const;

public:
    // custom exception handling and end-of-call checks
    virtual void callException(const std::exception  &e);
    virtual void callEnd();

protected:
    // logging
    void setOutcome(const XactOutcome &xo);
    virtual void finalizeLogInfo();

    ServiceRep &service();

private:
    void tellQueryAborted();
    void maybeLog();

protected:
    int connection;     // FD of the ICAP server connection
    Adaptation::Icap::ServiceRep::Pointer theService;

    /*
     * We have two read buffers.   We would prefer to read directly
     * into the MemBuf, but since comm_read isn't MemBuf-aware, and
     * uses event-delayed callbacks, it leaves the MemBuf in an
     * inconsistent state.  There would be data in the buffer, but
     * MemBuf.size won't be updated until the (delayed) callback
     * occurs.   To avoid that situation we use a plain buffer
     * (commBuf) and then copy (append) its contents to readBuf in
     * the callback.  If comm_read ever becomes MemBuf-aware, we
     * can eliminate commBuf and this extra buffer copy.
     */
    MemBuf readBuf;
    char *commBuf;
    size_t commBufSize;
    bool commEof;
    bool reuseConnection;
    bool isRetriable;  ///< can retry on persistent connection failures
    bool isRepeatable; ///< can repeat if no or unsatisfactory response
    bool ignoreLastWrite;

    const char *stopReason;

    // active (pending) comm callbacks for the ICAP server connection
    AsyncCall::Pointer connector;
    AsyncCall::Pointer reader;
    AsyncCall::Pointer writer;
    AsyncCall::Pointer closer;

    AccessLogEntry al;

    timeval icap_tr_start;     /*time when the ICAP transaction was created */
    timeval icap_tio_start;    /*time when the first ICAP request byte was scheduled for sending*/
    timeval icap_tio_finish;   /*time when the last byte of the ICAP responsewas received*/

private:
    //CBDATA_CLASS2(Xaction);
};


} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPXACTION_H */
