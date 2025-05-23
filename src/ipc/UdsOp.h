/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_SRC_IPC_UDSOP_H
#define SQUID_SRC_IPC_UDSOP_H

#include "base/AsyncJob.h"
#include "base/forward.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "ipc/FdNotes.h"
#include "ipc/TypedMsgHdr.h"
#include "SquidString.h"

class CommTimeoutCbParams;
class CommIoCbParams;

namespace Ipc
{

/// code shared by unix-domain socket senders (e.g., UdsSender or Coordinator)
/// and receivers (e.g. Port or Coordinator)
class UdsOp: public AsyncJob
{
public:
    UdsOp(const String &pathAddr);
    ~UdsOp() override;

public:
    struct sockaddr_un address; ///< UDS address from path; treat as read-only

protected:
    virtual void timedout() {} ///< called after setTimeout() if timed out

    Comm::ConnectionPointer &conn(); ///< creates if needed and returns raw UDS socket descriptor

    /// call timedout() if no UDS messages in a given number of seconds
    void setTimeout(time_t seconds, const char *handlerName);
    void clearTimeout(); ///< remove previously set timeout, if any

    void setOptions(int newOptions); ///< changes socket options

private:
    /// Comm timeout callback; calls timedout()
    void noteTimeout(const CommTimeoutCbParams &p);

private:
    int options; ///< UDS options
    Comm::ConnectionPointer conn_; ///< UDS descriptor

private:
    UdsOp(const UdsOp &); // not implemented
    UdsOp &operator= (const UdsOp &); // not implemented
};

/// converts human-readable filename path into UDS address
struct sockaddr_un PathToAddress(const String &pathAddr);

// XXX: move UdsSender code to UdsSender.{cc,h}
/// attempts to send an IPC message a few times, with a timeout
class UdsSender: public UdsOp
{
    CBDATA_CHILD(UdsSender);

public:
    UdsSender(const String& pathAddr, const TypedMsgHdr& aMessage);

    CodeContextPointer codeContext;

protected:
    void swanSong() override; // UdsOp (AsyncJob) API
    void start() override; // UdsOp (AsyncJob) API
    bool doneAll() const override; // UdsOp (AsyncJob) API
    void timedout() override; // UdsOp API

private:
    void startSleep();
    void cancelSleep();
    static void DelayedRetry(void *data);
    void delayedRetry();

    void write(); ///< schedule writing
    void wrote(const CommIoCbParams& params); ///< done writing or error

private:
    TypedMsgHdr message; ///< what to send
    int retries; ///< how many times to try after a write error
    time_t timeout; ///< total time to send the message
    bool sleeping; ///< whether we are waiting to retry a failed write
    bool writing; ///< whether Comm started and did not finish writing

private:
    UdsSender(const UdsSender&); // not implemented
    UdsSender& operator= (const UdsSender&); // not implemented
};

void SendMessage(const String& toAddress, const TypedMsgHdr& message);
/// import socket fd from another strand into our Comm state
const Comm::ConnectionPointer & ImportFdIntoComm(const Comm::ConnectionPointer &conn, int socktype, int protocol, FdNoteId noteId);

}

#endif /* SQUID_SRC_IPC_UDSOP_H */

