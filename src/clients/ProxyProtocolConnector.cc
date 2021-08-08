/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CachePeer.h"
#include "clients/ProxyProtocolConnector.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "http.h"
#include "neighbors.h"
#include "pconn.h"
#include "SquidConfig.h"
#include "StatCounters.h"

CBDATA_NAMESPACED_CLASS_INIT(ProxyProtocol, Connector);

ProxyProtocol::Connector::Connector(const Comm::ConnectionPointer &conn, const HttpRequestPointer &req, AsyncCall::Pointer &aCallback, const AccessLogEntryPointer &alp):
    AsyncJob("ProxyProtocol::Connector"),
    xaction(req->masterXaction),
    connection(conn),
    callback(aCallback),
    request(req),
    al(alp)
{
    debugs(83, 5, "ProxyProtocol::Connector constructed, this=" << (void*)this);
    // detect callers supplying cb dialers that are not our CbDialer
    assert(connection);
    assert(callback);
    peer = conn->getPeer();
    watchForClosures();
}

ProxyProtocol::Connector::~Connector()
{
    debugs(83, 5, "ProxyProtocol::Connector destructed, this=" << (void*)this);
}

bool
ProxyProtocol::Connector::doneAll() const
{
    return !callback;
}

void
ProxyProtocol::Connector::start()
{
    AsyncJob::start();

    // we own this Comm::Connection object and its fd exclusively, but must bail
    // if others started closing the socket while we were waiting to start()
    assert(Comm::IsConnOpen(connection));
    if (fd_table[connection->fd].closing()) {
        bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al));
        return;
    }

    // bail if our peer was reconfigured away
    if (!peer) {
        bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scInternalServerError, request.getRaw(), al));
        return;
    }

    writeRequest();
}

void
ProxyProtocol::Connector::handleConnectionClosure(const CommCloseCbParams &params)
{
    closer = nullptr;
    bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al));
}

/// make sure we quit if/when the connection is gone
void
ProxyProtocol::Connector::watchForClosures()
{
    Must(Comm::IsConnOpen(connection));
    Must(!fd_table[connection->fd].closing());

    debugs(83, 5, connection);

    Must(!closer);
    typedef CommCbMemFunT<ProxyProtocol::Connector, CommCloseCbParams> Dialer;
    closer = JobCallback(9, 5, Dialer, this, ProxyProtocol::Connector::handleConnectionClosure);
    comm_add_close_handler(connection->fd, closer);
}

void
ProxyProtocol::Connector::writeRequest()
{
    debugs(83, 5, connection);

    Two::Command cmd;
    Ip::Address srcIp;
    Ip::Address dstIp;
    if (xaction->tcpClient) {
        // pass client connection details
        cmd = Two::cmdProxy;
        srcIp = xaction->tcpClient->remote;
        dstIp = xaction->tcpClient->local;
    } else {
        // no client exists (Squid is the client)
        cmd = Two::cmdLocal;
        srcIp = connection->local;
        dstIp = connection->remote;
    }

    MemBuf mb;
    mb.init();

    if (peer->proxyp.version == 1) {
#if USE_IPV6
        const auto family = (srcIp.isIPv4() ? AF_INET : AF_INET6);
#else
        assert(srcIp.isIPv4());
        const auto family = AF_INET;
#endif
        char dip[MAX_IPSTRLEN];
        dstIp.toStr(dip, sizeof(dip)-1, family);
        char sip[MAX_IPSTRLEN];
        srcIp.toStr(sip, sizeof(sip)-1, family);

        mb.appendf("PROXY TCP%d %s %s %d %d\r\n", (family==AF_INET?4:6), sip, dip, srcIp.port(), dstIp.port());

    } else if (peer->proxyp.version == 2) {
        char c = '\0';
        // PROXYv2 magic prefix
        mb.append("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
        // version | command
        c = 0x20 | cmd;
        mb.append(&c, 1);
        // family | transport
        c = ((srcIp.isIPv4()? Two::afInet : Two::afInet6)<<4) | Two::tpStream;
        mb.append(&c, 1);

        // assemble IP:port info data
        ProxyProtocol::Addr ips;
        uint16_t ipaSz = 0;
        if (srcIp.isIPv4()) {
            srcIp.getAddr(ips.ip4.src_addr);
            ips.ip4.src_port = srcIP.port();
            dstIp.getAddr(ips.ip4.dst_addr);
            ips.ip4.dst_port = dstIP.port();
            ipaSz = sizeof(ips.ip4);
        } else {
#if USE_IPV6
            srcIp.getAddr(ips.ip6.src_addr);
            ips.ip6.src_port = srcIP.port();
            dstIp.getAddr(ips.ip6.dst_addr);
            ips.ip6.dst_port = dstIP.port();
            ipaSz = sizeof(ips.ip6);
#else
            assert(srcIp.isIPv4());
#endif
        }

        // XXX: assemble TLVs

        uint16_t len = htons((family==AF_INET? 4 : 16)*2 + 2*2) + ipaSz;
        mb.append(static_cast<char*>(&len), 2);

        // buffer IP:port data for write
        if (srcIp.isIPv4())
            mb.append(static_cast<char*>(&ips.ip4), ipaSz);
#if USE_IPV6
        else
            mb.append(static_cast<char*>(&ips.ip6), ipaSz);
#endif

        // XXX: buffer TLVs for write

    } else {
        // unsupported version for PROXY protocol
        bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scBadGateway, request.getRaw(), al));
        return;
    }

    debugs(11, 2, "PROXY Server REQUEST: " << connection <<
           ":\n----------\n" << mb.buf << "\n----------");
    fd_note(connection->fd, "PROXY tunnel");

    typedef CommCbMemFunT<ProxyProtocol::Connector, CommIoCbParams> Dialer;
    writer = JobCallback(5, 5, Dialer, this, ProxyProtocol::Connector::handleWrittenRequest);
    Comm::Write(connection, &mb, writer);
}

/// called when we are done writing the PROXY header to a peer
void
ProxyProtocol::Connector::handleWrittenRequest(const CommIoCbParams &io)
{
    Must(writer);
    writer = nullptr;

    if (io.flag == Comm::ERR_CLOSING)
        return;

    request->hier.notePeerWrite();

    if (io.flag != Comm::OK) {
        const auto error = new ErrorState(ERR_WRITE_ERROR, Http::scBadGateway, request.getRaw(), al);
        error->xerrno = io.xerrno;
        bailWith(error);
        return;
    }

    statCounter.server.all.kbytes_out += io.size;
    statCounter.server.other.kbytes_out += io.size;
    debugs(83, 5, status());
}

void
ProxyProtocol::Connector::bailWith(ErrorState *error)
{
    Must(error);
    answer().squidError = error;

    if (const auto p = connection->getPeer())
        peerConnectFailed(p);

    callBack();
    disconnect();

    connection->close();
    connection = nullptr;
}

void
ProxyProtocol::Connector::sendSuccess()
{
    assert(answer().positive());
    callBack();
    disconnect();
}

void
ProxyProtocol::Connector::disconnect()
{
    if (closer) {
        comm_remove_close_handler(connection->fd, closer);
        closer = nullptr;
    }
}

/// convenience method to get to the answer fields
Http::TunnelerAnswer &
ProxyProtocol::Connector::answer()
{
    Must(callback);
    const auto tunnelerAnswer = dynamic_cast<Http::TunnelerAnswer *>(callback->getDialer());
    Must(tunnelerAnswer);
    return *tunnelerAnswer;
}

void
ProxyProtocol::Connector::callBack()
{
    debugs(83, 5, connection << status());
    if (answer().positive())
        answer().conn = connection;
    auto cb = callback;
    callback = nullptr;
    ScheduleCallHere(cb);
}

void
ProxyProtocol::Connector::swanSong()
{
    AsyncJob::swanSong();

    if (callback) {
        // we should have bailed when we discovered the job-killing problem
        debugs(83, DBG_IMPORTANT, "BUG: Unexpected state while establishing a PROXY tunnel " << connection << status());
        bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
    }
}

const char *
ProxyProtocol::Connector::status() const
{
    static MemBuf buf;
    buf.reset();

    // TODO: redesign AsyncJob::status() API to avoid
    // id and stop reason reporting duplication.
    buf.append(" [state:", 8);
    if (!callback) buf.append("x", 1); // caller informed
    if (stopReason != nullptr) {
        buf.append(" stopped, reason:", 16);
        buf.appendf("%s",stopReason);
    }
    if (connection != nullptr)
        buf.appendf(" FD %d", connection->fd);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

