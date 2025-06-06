/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#ifndef SQUID_SRC_SERVERS_SERVER_H
#define SQUID_SRC_SERVERS_SERVER_H

#include "anyp/forward.h"
#include "anyp/ProtocolVersion.h"
#include "base/AsyncJob.h"
#include "BodyPipe.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "error/forward.h"
#include "http/Stream.h"
#include "log/forward.h"
#include "Pipeline.h"
#include "sbuf/SBuf.h"
#include "servers/forward.h"

/**
 * Common base for all Server classes used
 * to manage connections from clients.
 */
class Server : virtual public AsyncJob, public BodyProducer
{
public:
    Server(const MasterXactionPointer &xact);
    ~Server() override {}

    /* AsyncJob API */
    void start() override;
    bool doneAll() const override;
    void swanSong() override;

    /// whether to stop serving our client after reading EOF on its connection
    virtual bool shouldCloseOnEof() const = 0;

    /// maybe grow the inBuf and schedule Comm::Read()
    void readSomeData();

    /**
     * called when new request data has been read from the socket
     *
     * \retval false called comm_close or setReplyToError (the caller should bail)
     * \retval true  we did not call comm_close or setReplyToError
     */
    virtual bool handleReadData() = 0;

    /// processing to be done after a Comm::Read()
    virtual void afterClientRead() = 0;

    /// whether Comm::Read() is scheduled
    bool reading() const {return reader != nullptr;}

    /// cancels Comm::Read() if it is scheduled
    void stopReading();

    /// Update flags and timeout after the first byte received
    virtual void receivedFirstByte() = 0;

    /// maybe find some data to send and schedule a Comm::Write()
    virtual void writeSomeData() {}

    /// schedule some data for a Comm::Write()
    void write(MemBuf *mb) {
        typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
        writer = JobCallback(33, 5, Dialer, this, Server::clientWriteDone);
        Comm::Write(clientConnection, mb, writer);
    }

    /// schedule some data for a Comm::Write()
    void write(char *buf, int len) {
        typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
        writer = JobCallback(33, 5, Dialer, this, Server::clientWriteDone);
        Comm::Write(clientConnection, buf, len, writer, nullptr);
    }

    /// processing to sync state after a Comm::Write()
    virtual void afterClientWrite(size_t) {}

    /// whether Comm::Write() is scheduled
    bool writing() const {return writer != nullptr;}

// XXX: should be 'protected:' for child access only,
//      but all sorts of code likes to play directly
//      with the I/O buffers and socket.
public:

    /// grows the available read buffer space (if possible)
    void maybeMakeSpaceAvailable();

    // Client TCP connection details from comm layer.
    Comm::ConnectionPointer clientConnection;

    /**
     * The transfer protocol currently being spoken on this connection.
     * HTTP/1.x CONNECT, HTTP/1.1 Upgrade and HTTP/2 SETTINGS offer the
     * ability to change protocols on the fly.
     */
    AnyP::ProtocolVersion transferProtocol;

    /// Squid listening port details where this connection arrived.
    AnyP::PortCfgPointer port;

    /// read I/O buffer for the client connection
    SBuf inBuf;

    bool receivedFirstByte_; ///< true if at least one byte received on this connection

    /// set of requests waiting to be serviced
    Pipeline pipeline;

protected:
    /// abort any pending transactions and prevent new ones (by closing)
    virtual void terminateAll(const Error &, const LogTagsErrors &) = 0;

    /// whether client_request_buffer_max_size allows inBuf.length() increase
    bool mayBufferMoreRequestBytes() const;

    void doClientRead(const CommIoCbParams &io);
    void clientWriteDone(const CommIoCbParams &io);

    AsyncCall::Pointer reader; ///< set when we are reading
    AsyncCall::Pointer writer; ///< set when we are writing
};

#endif /* SQUID_SRC_SERVERS_SERVER_H */

