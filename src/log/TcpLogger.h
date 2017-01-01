/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_LOG_TCPLOGGER_H
#define _SQUID_SRC_LOG_TCPLOGGER_H

#include "base/AsyncJob.h"
#include "ip/Address.h"

#include <list>

class MemBlob;
typedef RefCount<MemBlob> MemBlobPointer;

namespace Log
{

/**
 * Sends log records to a remote TCP logger at the configured IP:port address.
 * Handles loss of connectivity, record buffering, and buffer overflows.
 */
class TcpLogger : public AsyncJob
{
public:
    typedef CbcPointer<TcpLogger> Pointer;

    /* Logfile API */
    static int Open(Logfile *lf, const char *path, size_t bufSz, int fatalFlag);

protected:
    TcpLogger(size_t, bool, Ip::Address);
    virtual ~TcpLogger();

    /// Called when Squid is reconfiguring (or exiting) to give us a chance to
    /// flush remaining buffers and end this job w/o loss of data. No new log
    /// records are expected. Must be used as (or inside) an async job call and
    /// will result in [eventual] job termination.
    void endGracefully();

    /// buffers record and possibly writes it to the remote logger
    void logRecord(const char *buf, size_t len);

    /// write all currently buffered records ASAP
    void flush();

    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

private:
    /* Logfile API. Map c-style Logfile calls to TcpLogger method calls. */
    static void Flush(Logfile *lf);
    static void WriteLine(Logfile *lf, const char *buf, size_t len);
    static void StartLine(Logfile *lf);
    static void EndLine(Logfile *lf);
    static void Rotate(Logfile *lf);
    static void Close(Logfile *lf);

    static TcpLogger *StillLogging(Logfile *lf);

    static void DelayedReconnect(void *data);
    void delayedReconnect();

    bool canFit(const size_t len) const;
    void appendRecord(const char *buf, size_t len);
    void appendChunk(const char *chunk, const size_t len);
    void writeIfNeeded();
    void writeIfPossible();
    void doConnect();
    void disconnect();

    /* comm callbacks */
    void connectDone(const CommConnectCbParams &conn);
    void writeDone(const CommIoCbParams &io);
    void handleClosure(const CommCloseCbParams &io);

    static const size_t IoBufSize; ///< fixed I/O buffer size
    static const size_t BufferCapacityMin; ///< minimum bufferCapacity value

    /// Whether this job must kill Squid on the first unrecoverable error.
    /// Note that we may be able to recover from a failure to connect, but we
    /// cannot recover from forgetting (dropping) a record while connecting.
    bool dieOnError;

    std::list<MemBlobPointer> buffers; ///< I/O buffers
    size_t bufferCapacity; ///< bufferedSize limit
    size_t bufferedSize; ///< number of log record bytes stored in RAM now
    size_t flushDebt; ///< how many record bytes we still need to write ASAP

    bool quitOnEmpty; ///< whether this job should quit when buffers are empty
    bool reconnectScheduled; ///< we are sleeping before the next connection attempt
    bool writeScheduled; ///< we are waiting for the latest write() results

    Comm::ConnectionPointer conn; ///< opened connection to the remote logger
    Ip::Address remote; ///< where the remote logger expects our records
    AsyncCall::Pointer closer; ///< handles unexpected/external conn closures

    uint64_t connectFailures; ///< number of sequential connection failures
    uint64_t drops; ///< number of records dropped during the current outage

    CBDATA_CLASS2(TcpLogger);
};

} // namespace Log

#endif /* _SQUID_SRC_LOG_TCPLOGGER_H */

