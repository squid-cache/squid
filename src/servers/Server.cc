/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "client_side.h"
#include "comm.h"
#include "comm/Read.h"
#include "debug/Stream.h"
#include "error/SysErrorDetail.h"
#include "fd.h"
#include "fde.h"
#include "http/Stream.h"
#include "LogTags.h"
#include "MasterXaction.h"
#include "servers/Server.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "tools.h"

Server::Server(const MasterXaction::Pointer &xact) :
    AsyncJob("::Server"), // kids overwrite
    clientConnection(xact->tcpClient),
    transferProtocol(xact->squidPort->transport),
    port(xact->squidPort),
    receivedFirstByte_(false)
{
    clientConnection->leaveOrphanage();
}

bool
Server::doneAll() const
{
    // servers are not done while the connection is open
    return !Comm::IsConnOpen(clientConnection) &&
           BodyProducer::doneAll();
}

void
Server::start()
{
    // TODO: shuffle activity from ConnStateData
}

void
Server::swanSong()
{
    if (Comm::IsConnOpen(clientConnection))
        clientConnection->close();

    BodyProducer::swanSong();
}

void
Server::stopReading()
{
    if (reading()) {
        Comm::ReadCancel(clientConnection->fd, reader);
        reader = nullptr;
    }
}

/// Prepare inBuf for I/O. This method balances several conflicting desires:
/// 1. Do not read too few bytes at a time.
/// 2. Do not waste too much buffer space.
/// 3. Do not [re]allocate or memmove the buffer too much.
/// 4. Obey Config.maxRequestBufferSize limit.
void
Server::maybeMakeSpaceAvailable()
{
    // The hard-coded parameters are arbitrary but seem reasonable.
    // A careful study of Squid I/O and parsing patterns is needed to tune them.
    SBufReservationRequirements requirements;
    requirements.minSpace = 1024; // smaller I/Os are not worth their overhead
    requirements.idealSpace = CLIENT_REQ_BUF_SZ; // we expect few larger I/Os
    requirements.maxCapacity = Config.maxRequestBufferSize;
    requirements.allowShared = true; // allow because inBuf is used immediately
    inBuf.reserve(requirements);
    if (!inBuf.spaceSize())
        debugs(33, 4, "request buffer full: client_request_buffer_max_size=" << Config.maxRequestBufferSize);
}

void
Server::readSomeData()
{
    if (reading())
        return;

    debugs(33, 4, clientConnection << ": reading request...");

    // we can only read if there is more than 1 byte of space free
    if (Config.maxRequestBufferSize - inBuf.length() < 2)
        return;

    typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
    reader = JobCallback(33, 5, Dialer, this, Server::doClientRead);
    Comm::Read(clientConnection, reader);
}

void
Server::doClientRead(const CommIoCbParams &io)
{
    debugs(33,5, io.conn);
    Must(reading());
    reader = nullptr;

    /* Bail out quickly on Comm::ERR_CLOSING - close handlers will tidy up */
    if (io.flag == Comm::ERR_CLOSING) {
        debugs(33,5, io.conn << " closing Bailout.");
        return;
    }

    assert(Comm::IsConnOpen(clientConnection));
    assert(io.conn->fd == clientConnection->fd);

    /*
     * Don't reset the timeout value here. The value should be
     * counting Config.Timeout.request and applies to the request
     * as a whole, not individual read() calls.
     * Plus, it breaks our lame *HalfClosed() detection
     */

    maybeMakeSpaceAvailable();
    CommIoCbParams rd(this); // will be expanded with ReadNow results
    rd.conn = io.conn;
    switch (Comm::ReadNow(rd, inBuf)) {
    case Comm::INPROGRESS:

        if (inBuf.isEmpty())
            debugs(33, 2, io.conn << ": no data to process, " << xstrerr(rd.xerrno));
        readSomeData();
        return;

    case Comm::OK:
        statCounter.client_http.kbytes_in += rd.size;
        if (!receivedFirstByte_)
            receivedFirstByte();
        // may comm_close or setReplyToError
        if (!handleReadData())
            return;

        /* Continue to process previously read data */
        break;

    case Comm::ENDFILE: // close detected by 0-byte read
        debugs(33, 5, io.conn << " closed?");

        if (shouldCloseOnEof()) {
            LogTagsErrors lte;
            lte.aborted = true;
            terminateAll(ERR_CLIENT_GONE, lte);
            return;
        }

        /* It might be half-closed, we can't tell */
        fd_table[io.conn->fd].flags.socket_eof = true;
        commMarkHalfClosed(io.conn->fd);
        fd_note(io.conn->fd, "half-closed");

        /* There is one more close check at the end, to detect aborted
         * (partial) requests. At this point we can't tell if the request
         * is partial.
         */

        /* Continue to process previously read data */
        break;

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
        debugs(33, 2, io.conn << ": got flag " << rd.flag << "; " << xstrerr(rd.xerrno));
        LogTagsErrors lte;
        lte.timedout = rd.xerrno == ETIMEDOUT;
        lte.aborted = !lte.timedout; // intentionally true for zero rd.xerrno
        terminateAll(Error(ERR_CLIENT_GONE, SysErrorDetail::NewIfAny(rd.xerrno)), lte);
        return;
    }

    afterClientRead();
}

/** callback handling the Comm::Write completion
 *
 * Will call afterClientWrite(size_t) to sync the I/O state.
 * Then writeSomeData() to initiate any followup writes that
 * could be immediately done.
 */
void
Server::clientWriteDone(const CommIoCbParams &io)
{
    debugs(33,5, io.conn);
    Must(writer != nullptr);
    writer = nullptr;

    /* Bail out quickly on Comm::ERR_CLOSING - close handlers will tidy up */
    if (io.flag == Comm::ERR_CLOSING || !Comm::IsConnOpen(clientConnection)) {
        debugs(33,5, io.conn << " closing Bailout.");
        return;
    }

    Must(io.conn->fd == clientConnection->fd);

    if (io.flag) {
        debugs(33, 2, "bailing after a write failure: " << xstrerr(io.xerrno));
        LogTagsErrors lte;
        lte.timedout = io.xerrno == ETIMEDOUT;
        lte.aborted = !lte.timedout; // intentionally true for zero io.xerrno
        terminateAll(Error(ERR_WRITE_ERROR, SysErrorDetail::NewIfAny(io.xerrno)), lte);
        return;
    }

    afterClientWrite(io.size); // update state
    writeSomeData(); // maybe schedules another write
}

