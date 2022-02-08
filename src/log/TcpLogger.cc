/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Loops.h"
#include "comm/Write.h"
#include "fatal.h"
#include "fde.h"
#include "globals.h" // for shutting_down
#include "log/CustomLog.h"
#include "log/File.h"
#include "log/TcpLogger.h"
#include "Parsing.h"
#include "sbuf/MemBlob.h"
#include "SquidConfig.h"
#include "SquidTime.h"

// a single I/O buffer should be large enough to store any access.log record
const size_t Log::TcpLogger::IoBufSize = 2*MAX_URL;

// We need at least two buffers because when we write the first buffer,
// we have to use the second buffer to accumulate new entries.
const size_t Log::TcpLogger::BufferCapacityMin = 2*Log::TcpLogger::IoBufSize;

#define MY_DEBUG_SECTION 50 /* Log file handling */

CBDATA_NAMESPACED_CLASS_INIT(Log, TcpLogger);

Log::TcpLogger::TcpLogger(size_t bufCap, bool dieOnErr, Ip::Address them):
    AsyncJob("TcpLogger"),
    dieOnError(dieOnErr),
    bufferCapacity(bufCap),
    bufferedSize(0),
    flushDebt(0),
    quitOnEmpty(false),
    reconnectScheduled(false),
    writeScheduled(false),
    conn(NULL),
    remote(them),
    connectFailures(0),
    drops(0)
{
    if (bufferCapacity < BufferCapacityMin) {
        debugs(MY_DEBUG_SECTION, DBG_IMPORTANT,
               "WARNING: tcp:" << remote << " logger configured buffer " <<
               "size " << bufferCapacity << " is smaller than the " <<
               BufferCapacityMin << "-byte" << " minimum. " <<
               "Using the minimum instead.");
        bufferCapacity = BufferCapacityMin;
    }
}

Log::TcpLogger::~TcpLogger()
{
    // make sure Comm::Write does not have our buffer pointer
    assert(!writeScheduled);
}

void
Log::TcpLogger::start()
{
    doConnect();
}

bool
Log::TcpLogger::doneAll() const
{
    debugs(MY_DEBUG_SECTION, 5, "quitOnEmpty: " << quitOnEmpty <<
           " buffered: " << bufferedSize <<
           " conn: " << conn << ' ' << connectFailures);

    // we do not quit unless we are told that we may
    if (!quitOnEmpty)
        return false;

    /* We were asked to quit after we are done writing buffers. Are we done? */

    // If we have records but are failing to connect, quit. Otherwise, we may
    // be trying to connect forever due to a [since fixed] misconfiguration!
    const bool failingToConnect = !conn && connectFailures;
    if (bufferedSize && !failingToConnect)
        return false;

    return AsyncJob::doneAll();
}

void
Log::TcpLogger::swanSong()
{
    disconnect(); // optional: refcounting should close/delete conn eventually
    AsyncJob::swanSong();
}

void
Log::TcpLogger::endGracefully()
{
    // job call protection must end our job if we are done logging current bufs
    assert(inCall != NULL);
    quitOnEmpty = true;
    flush();
}

void
Log::TcpLogger::flush()
{
    flushDebt = bufferedSize;
    writeIfNeeded();
}

void
Log::TcpLogger::logRecord(const char *buf, const size_t len)
{
    appendRecord(buf, len);
    writeIfNeeded();
}

/// starts writing if and only if it is time to write accumulated records
void
Log::TcpLogger::writeIfNeeded()
{
    // write if an earlier flush command forces us to write or
    // if we have filled at least one I/O buffer
    if (flushDebt > 0 || buffers.size() > 1)
        writeIfPossible();
}

/// starts writing if possible
void Log::TcpLogger::writeIfPossible()
{
    debugs(MY_DEBUG_SECTION, 7, "guards: " << (!writeScheduled) <<
           (bufferedSize > 0) << (conn != NULL) <<
           (conn != NULL && !fd_table[conn->fd].closing()) << " buffered: " <<
           bufferedSize << '/' << buffers.size());

    // XXX: Squid shutdown sequence starts closing our connection before
    // calling LogfileClose, leading to loss of log records during shutdown.
    if (!writeScheduled && bufferedSize > 0 && conn != NULL &&
            !fd_table[conn->fd].closing()) {
        debugs(MY_DEBUG_SECTION, 5, "writing first buffer");

        typedef CommCbMemFunT<TcpLogger, CommIoCbParams> WriteDialer;
        AsyncCall::Pointer callback = JobCallback(MY_DEBUG_SECTION, 5, WriteDialer, this, Log::TcpLogger::writeDone);
        const MemBlob::Pointer &buffer = buffers.front();
        Comm::Write(conn, buffer->mem, buffer->size, callback, NULL);
        writeScheduled = true;
    }
}

/// whether len more bytes can be buffered
bool
Log::TcpLogger::canFit(const size_t len) const
{
    // TODO: limit reporting frequency in addition to reporting only changes

    if (bufferedSize+len <= bufferCapacity) {
        if (drops) {
            // We can get here if a shorter record accidentally fits after we
            // started dropping records. When that happens, the following
            // DBG_IMPORTANT message will mislead admin into thinking that
            // the problem was resolved (for a brief period of time, until
            // another record comes in and overflows the buffer). It is
            // difficult to prevent this without also creating the opposite
            // problem: A huge record that does not fit and is dropped blocks
            // subsequent regular records from being buffered until we write.
            debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "tcp:" << remote <<
                   " logger stops dropping records after " << drops << " drops" <<
                   "; current buffer use: " << (bufferedSize+len) <<
                   " out of " << bufferCapacity << " bytes");
        }
        return true;
    }

    if (!drops || dieOnError) {
        debugs(MY_DEBUG_SECTION,
               dieOnError ? DBG_CRITICAL : DBG_IMPORTANT,
               "tcp:" << remote << " logger " << bufferCapacity << "-byte " <<
               "buffer overflowed; cannot fit " <<
               (bufferedSize+len-bufferCapacity) << " bytes");
    }

    if (dieOnError)
        fatal("tcp logger buffer overflowed");

    if (!drops) {
        debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "tcp:" << remote <<
               " logger starts dropping records.");
    }

    return false;
}

/// buffer a record that might exceed IoBufSize
void
Log::TcpLogger::appendRecord(const char *record, const size_t len)
{
    // they should not happen, but to be safe, let's protect drop start/stop
    // monitoring algorithm from empty records (which can never be dropped)
    if (!len)
        return;

    if (!canFit(len)) {
        ++drops;
        return;
    }

    drops = 0;
    // append without spliting buf, unless it exceeds IoBufSize
    for (size_t off = 0; off < len; off += IoBufSize)
        appendChunk(record + off, min(len - off, IoBufSize));
}

/// buffer a record chunk without splitting it across buffers
void
Log::TcpLogger::appendChunk(const char *chunk, const size_t len)
{
    Must(len <= IoBufSize);
    // add a buffer if there is not one that can accomodate len bytes
    bool addBuffer = buffers.empty() ||
                     (buffers.back()->size+len > IoBufSize);
    // also add a buffer if there is only one and that one is being written
    addBuffer = addBuffer || (writeScheduled && buffers.size() == 1);

    if (addBuffer) {
        buffers.push_back(new MemBlob(IoBufSize));
        debugs(MY_DEBUG_SECTION, 7, "added buffer #" << buffers.size());
    }

    Must(!buffers.empty());
    buffers.back()->append(chunk, len);
    bufferedSize += len;
}

/// starts [re]connecting to the remote logger
void
Log::TcpLogger::doConnect()
{
    if (shutting_down)
        return;

    debugs(MY_DEBUG_SECTION, 3, "connecting");
    Must(!conn);

    Comm::ConnectionPointer futureConn = new Comm::Connection;
    futureConn->remote = remote;
    futureConn->local.setAnyAddr();
    if (futureConn->remote.isIPv4())
        futureConn->local.setIPv4();

    typedef CommCbMemFunT<TcpLogger, CommConnectCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(MY_DEBUG_SECTION, 5, Dialer, this, Log::TcpLogger::connectDone);
    const auto cs = new Comm::ConnOpener(futureConn, call, 2);
    connWait.start(cs, call);
}

/// Comm::ConnOpener callback
void
Log::TcpLogger::connectDone(const CommConnectCbParams &params)
{
    connWait.finish();

    if (params.flag != Comm::OK) {
        const double delay = 0.5; // seconds
        if (connectFailures++ % 100 == 0) {
            debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "tcp:" << remote <<
                   " logger connection attempt #" << connectFailures <<
                   " failed. Will keep trying every " << delay << " seconds.");
        }

        if (!reconnectScheduled) {
            reconnectScheduled = true;
            eventAdd("Log::TcpLogger::DelayedReconnect",
                     Log::TcpLogger::DelayedReconnect,
                     new Pointer(this), 0.5, 0, false);
        }
    } else {
        if (connectFailures > 0) {
            debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "tcp:" << remote <<
                   " logger connectivity restored after " <<
                   (connectFailures+1) << " attempts.");
            connectFailures = 0;
        }

        Must(!conn);
        conn = params.conn;

        Must(!closer);
        typedef CommCbMemFunT<TcpLogger, CommCloseCbParams> Closer;
        closer = JobCallback(MY_DEBUG_SECTION, 4, Closer, this, Log::TcpLogger::handleClosure);
        comm_add_close_handler(conn->fd, closer);

        writeIfNeeded();
    }
}

// XXX: Needed until eventAdd() starts accepting Async calls directly.
/// Log::TcpLogger::delayedReconnect() wrapper.
void
Log::TcpLogger::DelayedReconnect(void *data)
{
    Pointer *ptr = static_cast<Pointer*>(data);
    assert(ptr);
    if (TcpLogger *logger = ptr->valid()) {
        // Get back inside AsyncJob protections by scheduling another call.
        typedef NullaryMemFunT<TcpLogger> Dialer;
        AsyncCall::Pointer call = JobCallback(MY_DEBUG_SECTION, 5, Dialer,
                                              logger,
                                              Log::TcpLogger::delayedReconnect);
        ScheduleCallHere(call);
    }
    delete ptr;
}

/// "sleep a little before trying to connect again" event callback
void
Log::TcpLogger::delayedReconnect()
{
    Must(reconnectScheduled);
    Must(!conn);
    reconnectScheduled = false;
    doConnect();
}

/// Comm::Write callback
void
Log::TcpLogger::writeDone(const CommIoCbParams &io)
{
    writeScheduled = false;
    if (io.flag == Comm::ERR_CLOSING) {
        debugs(MY_DEBUG_SECTION, 7, "closing");
        // do nothing here -- our comm_close_handler will be called to clean up
    } else if (io.flag != Comm::OK) {
        debugs(MY_DEBUG_SECTION, 2, "write failure: " << xstrerr(io.xerrno));
        // keep the first buffer (the one we failed to write)
        disconnect();
        doConnect();
    } else {
        debugs(MY_DEBUG_SECTION, 5, "write successful");

        Must(!buffers.empty()); // we had a buffer to write
        const MemBlob::Pointer &written = buffers.front();
        const size_t writtenSize = static_cast<size_t>(written->size);
        // and we wrote the whole buffer
        Must(io.size == writtenSize);
        Must(bufferedSize >= writtenSize);
        bufferedSize -= writtenSize;

        buffers.pop_front();

        if (flushDebt > io.size)
            flushDebt -= io.size;
        else
            flushDebt = 0; // wrote everything we owed (or more)

        writeIfNeeded();
    }
}

/// This is our comm_close_handler. It is called when some external force
/// (e.g., reconfigure or shutdown) is closing the connection (rather than us).
void
Log::TcpLogger::handleClosure(const CommCloseCbParams &)
{
    assert(inCall != NULL);
    closer = NULL;
    if (conn) {
        conn->noteClosure();
        conn = nullptr;
    }
    // in all current use cases, we should not try to reconnect
    mustStop("Log::TcpLogger::handleClosure");
}

/// close our connection now, without flushing
void
Log::TcpLogger::disconnect()
{
    if (conn != NULL) {
        if (closer != NULL) {
            comm_remove_close_handler(conn->fd, closer);
            closer = NULL;
        }
        conn->close();
        conn = NULL;
    }
}

/// Converts Logfile into a pointer to a valid TcpLogger job or,
/// if the logger job has quit, into a nill pointer
Log::TcpLogger *
Log::TcpLogger::StillLogging(Logfile *lf)
{
    if (Pointer *pptr = static_cast<Pointer*>(lf->data))
        return pptr->get(); // may be nil
    return NULL;
}

void
Log::TcpLogger::Flush(Logfile * lf)
{
    if (TcpLogger *logger = StillLogging(lf))
        logger->flush();
}

void
Log::TcpLogger::WriteLine(Logfile * lf, const char *buf, size_t len)
{
    if (TcpLogger *logger = StillLogging(lf))
        logger->logRecord(buf, len);
}

void
Log::TcpLogger::StartLine(Logfile *)
{
}

void
Log::TcpLogger::EndLine(Logfile * lf)
{
    if (!Config.onoff.buffered_logs)
        Flush(lf);
}

void
Log::TcpLogger::Rotate(Logfile *, const int16_t)
{
}

void
Log::TcpLogger::Close(Logfile * lf)
{
    if (TcpLogger *logger = StillLogging(lf)) {
        debugs(50, 3, "Closing " << logger);
        typedef NullaryMemFunT<TcpLogger> Dialer;
        Dialer dialer(logger, &Log::TcpLogger::endGracefully);
        AsyncCall::Pointer call = asyncCall(50, 3, "Log::TcpLogger::endGracefully", dialer);
        ScheduleCallHere(call);
    }
    delete static_cast<Pointer*>(lf->data);
    lf->data = NULL;
}

/*
 * This code expects the path to be //host:port
 */
int
Log::TcpLogger::Open(Logfile * lf, const char *path, size_t bufsz, int fatalFlag)
{
    assert(!StillLogging(lf));
    debugs(5, 3, "Tcp Open called");

    Ip::Address addr;

    if (strncmp(path, "//", 2) == 0)
        path += 2;
    char *strAddr = xstrdup(path);
    if (!GetHostWithPort(strAddr, &addr)) {
        if (lf->flags.fatal) {
            fatalf("Invalid TCP logging address '%s'\n", lf->path);
        } else {
            debugs(50, DBG_IMPORTANT, "Invalid TCP logging address '" << lf->path << "'");
            safe_free(strAddr);
            return FALSE;
        }
    }
    safe_free(strAddr);

    TcpLogger *logger = new TcpLogger(bufsz, fatalFlag, addr);
    lf->data = new Pointer(logger);
    lf->f_close = &Close;
    lf->f_linewrite = &WriteLine;
    lf->f_linestart = &StartLine;
    lf->f_lineend = &EndLine;
    lf->f_flush = &Flush;
    lf->f_rotate = &Rotate;
    AsyncJob::Start(logger);

    return 1;
}

