
/*
 * $Id: ICAPXaction.h,v 1.11 2007/05/08 16:32:12 rousskov Exp $
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
#include "MemBuf.h"
#include "ICAPServiceRep.h"
#include "ICAPInitiate.h"

class HttpMsg;

/*
 * The ICAP Xaction implements common tasks for ICAP OPTIONS, REQMOD, and
 * RESPMOD transactions. It is started by an ICAPInitiator. It terminates
 * on its own, when done. Transactions communicate with Initiator using
 * asynchronous messages because a transaction or Initiator may be gone at
 * any time.
 */

// Note: ICAPXaction must be the first parent for object-unaware cbdata to work

class ICAPXaction: public ICAPInitiate
{

public:
    ICAPXaction(const char *aTypeName, ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService);
    virtual ~ICAPXaction();

    void disableRetries();

    // comm handler wrappers, treat as private
    void noteCommConnected(comm_err_t status);
    void noteCommWrote(comm_err_t status, size_t sz);
    void noteCommRead(comm_err_t status, size_t sz);
    void noteCommTimedout();
    void noteCommClosed();

protected:
    virtual void start();
    virtual void noteInitiatorAborted(); // TODO: move to ICAPInitiate

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

    // custom end-of-call checks
    virtual void callEnd();

protected:
    const int id; // transaction ID for debugging, unique across ICAP xactions

    int connection;     // FD of the ICAP server connection

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
    bool isRetriable;

    const char *stopReason;

    // active (pending) comm callbacks for the ICAP server connection
    CNCB *connector;
    IOCB *reader;
    IOCB *writer;
    PF *closer;

    const char *typeName; // the type of the final class (child), for debugging

private:
    static int TheLastId;

    const char *inCall; // name of the asynchronous call being executed, if any

    static void reusedConnection(void *data);

    //CBDATA_CLASS2(ICAPXaction);
};

// call guards for all "asynchronous" note*() methods
// If we move ICAPXaction_* macros to core, they can use these generic names:
#define ICAPXaction_Enter(method) AsyncCallEnter(method)
#define ICAPXaction_Exit() AsyncCallExit()

#endif /* SQUID_ICAPXACTION_H */
