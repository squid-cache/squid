/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Listener Socket Handler */
/* DEBUG: section 94    QUIC Protocol */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "comm.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "log/access_log.h"
#include "parser/BinaryTokenizer.h"
#include "quic/Acceptor.h"
#include "quic/Connection.h"
#include "sbuf/SBuf.h"

#include <cerrno>

CBDATA_NAMESPACED_CLASS_INIT(Quic, Acceptor);

Quic::Acceptor::Acceptor(const AnyP::PortCfgPointer &p) :
    AsyncJob("Quic::Acceptor"),
    listenConn(p->listenConn),
    listenPort(p),
    clients((1<<21) /* 2MB cap */, (5*60) /* 3min TTL */)
{}

void
Quic::Acceptor::start()
{
    debugs(94, 2, listenConn);

    Must(listenPort);
    CodeContext::Reset(listenPort);

    Must(IsConnOpen(listenConn));

    typedef CommCbMemFunT<Quic::Acceptor, CommCloseCbParams> Dialer;
    closer = JobCallback(5, 4, Dialer, this, Quic::Acceptor::handleClosure);
    comm_add_close_handler(listenConn->fd, closer);

    listenConn->noteStart();
    readSomeData();
}

bool
Quic::Acceptor::doneAll() const
{
    // stop when FD is closed
    if (!IsConnOpen(listenConn))
        return AsyncJob::doneAll();

    // open FD with handlers...keep accepting.
    return false;
}

void
Quic::Acceptor::swanSong()
{
    if (IsConnOpen(listenConn)) {
        if (closer)
            comm_remove_close_handler(listenConn->fd, closer);
        listenConn->close();
    }

    listenConn = nullptr;
    AsyncJob::swanSong();
}

const char *
Quic::Acceptor::status() const
{
    if (listenConn == nullptr)
        return "[nil connection]";

    static char ipbuf[MAX_IPSTRLEN] = {'\0'};
    if (ipbuf[0] == '\0')
        listenConn->local.toHostStr(ipbuf, MAX_IPSTRLEN);

    static SBuf buf;
    buf.appendf(" FD %d, %s", listenConn->fd, ipbuf);

    const char *jobStatus = AsyncJob::status();
    buf.append(jobStatus, strlen(jobStatus));

    return buf.c_str();
}

void
Quic::Acceptor::readSomeData()
{
    debugs(5, 4, listenConn << ": reading request...");

    typedef CommCbMemFunT<Quic::Acceptor, CommIoCbParams> Dialer;
    reader = JobCallback(5, 5, Dialer, this, Quic::Acceptor::doClientRead);
    Comm::Read(listenConn, reader);
}

/// called when listening descriptor is closed by an external force
/// such as clientHttpConnectionsClose()
void
Quic::Acceptor::handleClosure(const CommCloseCbParams &)
{
    closer = nullptr;
    if (listenConn) {
        listenConn->noteClosure();
        listenConn = nullptr;
    }
    Must(done());
}

void
Quic::Acceptor::logAcceptError() const
{
    AccessLogEntry::Pointer al = new AccessLogEntry;
    CodeContext::Reset(al);
    al->url = "error:QUIC-client-connection";
    al->setVirginUrlForMissingRequest(al->url);
    ACLFilledChecklist ch(nullptr, nullptr, nullptr);
    ch.my_addr = listenConn->local;
    ch.al = al;
    accessLogLog(al, &ch);

    CodeContext::Reset(listenPort);
}

void
Quic::Acceptor::doClientRead(const CommIoCbParams &io)
{
    if (io.flag == Comm::COMM_ERROR) {
        debugs(5, DBG_IMPORTANT, "ERROR: non-recoverable error: " << status());
        logAcceptError();
        mustStop("Listener socket closed");
        return;
    }

    Ip::Address from;
    for (int max = INCOMING_UDP_MAX; max ; --max) try {
        SBuf buf;
        auto *data = buf.rawAppendStart(SQUID_UDP_SO_RCVBUF);
        int len = comm_udp_recvfrom(io.fd, data, buf.spaceSize(), 0, from);
        if (len > 0)
            buf.rawAppendFinish(data, len);

        if (len == 0)
            break;

        if (len < 0) {
            xerrno = errno;
            if (ignoreErrno(xerrno))
                break;

#if _SQUID_LINUX_
            /* Some Linux systems seem to set the FD for reading and then
             * return ECONNREFUSED when sendto() fails and generates an ICMP
             * port unreachable message. */
            /* or maybe an EHOSTUNREACH "No route to host" message */
            if (xerrno != ECONNREFUSED && xerrno != EHOSTUNREACH)
#endif
                debugs(5, DBG_IMPORTANT, "FD " << io.fd << " recvfrom: " << xstrerr(xerrno));
            break;
        }

        debugs(94, 4, "FD " << io.fd << ": received " << len << " bytes from " << from);
        debugs(94, 9, Raw("data", buf.rawContent(), buf.length()).hex());

        // ignore ICP packets which loop back (multicast usually)
        if (listenConn->local == from) {
            debugs(94, 2, "ignoring packet sent by myself");
            continue;
        }

        dispatch(buf, from);

    } catch (...) {
        debugs(94, DBG_IMPORTANT, "ERROR: unhandled exception processing QUIC packet from " << from);
    }

    readSomeData();
}

uint64_t
Quic::Acceptor::decodeVarInt(::Parser::BinaryTokenizer &tok, const char *description)
{
    auto msb = tok.uint8(description);
    uint64_t result = (msb & 0x3F);
    uint8_t len = 2 ^ ((msb & 0xC0) >> 6);
    Must(tok.leftovers().length() >= len);
    for (; len ; --len) {
        result <<= 8;
        result += tok.uint8(description);
    }
    return result;
}

SBuf
Quic::Acceptor::getToken(::Parser::BinaryTokenizer &tok)
{
    auto len = decodeVarInt(tok, "token-length");
    Must(tok.leftovers().length() >= len);
    return tok.area(len, "token");
}

uint64_t
Quic::Acceptor::getPayloadLength(::Parser::BinaryTokenizer &tok)
{
    auto len = decodeVarInt(tok, "length");
    Must(tok.leftovers().length() >= len);
    return len;
}

uint64_t
Quic::Acceptor::getPacketNumber(::Parser::BinaryTokenizer &tok, uint8_t nl)
{
    switch (nl & QUIC_RFC9000_PTYPE_NLEN) {
    case 0:
        return tok.uint8("number");
    case 1:
        return tok.uint16("number");
    case 2:
        return tok.uint24("number");
    case 3:
        return tok.uint32("number");
    }
    return 0; // unreachable
}

/// Determine QUIC version-agnostic details and initiate a Server to handle the packet received.
/// Governed by RFC 8999
void
Quic::Acceptor::dispatch(const SBuf &buf, Ip::Address &from)
{
    // TODO: support NAT, TPROXY, EUI and NF ConnMark on UDP traffic

    ::Parser::BinaryTokenizer tok(buf);
    Quic::ConnectionPointer pkt = new Quic::Connection();
    pkt->clientAddress = from;
    pkt->vsBits = tok.uint8("QUIC-version-specific-bits");

    // discard QUIC Short packets as unsupported
    if ((pkt->vsBits & QUIC_PACKET_TYPE_MASK) == 0) {
        debugs(94, 4, "ignoring unsupported 'Short' packet type from " << from);
        return;
    }

    pkt->version = ntohl(tok.uint32("QUIC-version"));
    uint32_t dstIdLen = tok.uint8("QUIC-dst-connection-ID-length");
    if (dstIdLen > 0) {
        pkt->dstConnectionId = tok.area(dstIdLen, "QUIC-dst-connection-ID");
        debugs(94, 8, "dst " << Raw("CID", pkt->dstConnectionId.rawContent(), pkt->dstConnectionId.length()).hex());
    }
    uint32_t srcIdLen = tok.uint8("QUIC-src-connection-ID-length");
    if (srcIdLen > 0) {
        pkt->srcConnectionId = tok.area(srcIdLen,"QUIC-src-connection-ID");
        debugs(94, 8, "src " << Raw("CID", pkt->srcConnectionId.rawContent(), pkt->srcConnectionId.length()).hex());
    }

    debugs(94, 2, "QUIC client, FD " << listenConn->fd << ", remote=" << from);
    debugs(94, 2, "QUIC packet header " << tok.parsed() << " bytes");

    if (pkt->version == QUIC_VERSION_NEGOTIATION) {
        debugs(94, 3, "ignoring attempt to negotiate version change from " << from);
        return;

    } else if ((pkt->vsBits & QUIC_RFC9000_PACKET_VALID)) {
        // RFC 9000 section 17.2 bit claiming a valid QUIC compliant packet found
        debugs(94, 4, "confirmed QUIC packet type=0x" << AsHex(pkt->vsBits & QUIC_RFC9000_PTYPE) << " from " << from);

        // RFC 9000 forced version (re-)negotiation
        if ((pkt->version & QUIC_VERSION_FORCE_NEGOTIATE_MASK) == QUIC_VERSION_FORCE_NEGOTIATE_MASK) {
            debugs(94, 3, "forced version change from " << from);
            negotiateVersion(*pkt);
            return;
        }

        int pType = (pkt->vsBits & QUIC_RFC9000_PTYPE);
        // RFC 9000 section Retry packet is server-to-client only
        // higher packet numbers are not supported
        if (pType > 0x02) {
            debugs(94, 3, "unknown type=0x" << AsHex(pkt->vsBits & QUIC_RFC9000_PTYPE) << " from " << from);
            return;
        }

        // RFC 9000 section 17.2.2 Initial Packet
        if (pType == 0x00)
            pkt->token = getToken(tok);

        auto plen = getPayloadLength(tok);
        auto number = getPacketNumber(tok, pkt->vsBits);
        auto payload = tok.area(plen -1 -(pkt->vsBits & QUIC_RFC9000_PTYPE_NLEN), "payload");
        if (!tok.atEnd()) {
            debugs(94, 2, "ignoring garbage input" << Raw("buf",tok.leftovers().rawContent(), tok.leftovers().length()));
        }

        SBuf key = clientCacheKey(pkt);
        if (auto clientConn = clients.get(key)) {
            debugs(94, 3, "existing QUIC client connection" << Raw("key",key.rawContent(), key.length()).hex());
            (*clientConn)->inQueue.emplace_back(number, payload);
// XXX: sort the inQueue by number before spawning the Call
// spawn a clientConn->notifyOnClientRead Call to handle the new data

        } else {
            pkt->inQueue.emplace_back(number, payload);
            clients.add(key, pkt);
            debugs(94, 3, "new QUIC client connection" << Raw("key",key.rawContent(), key.length()).hex());
            // TODO: implement Quic::NewServer(pkt, tok)
        }
        return;

    } else {
        // reject unsupported QUIC versions
        debugs(94, 3, "ignoring unknown version " << pkt->version << " from " << from);
        return;
    }
}

void
Quic::Acceptor::negotiateVersion(Connection &c)
{
    SBuf out;
    // see RFC 9000 section 17.2.1 version-specific bits requirements
    out.append(char(QUIC_PACKET_TYPE_MASK | QUIC_RFC9000_PACKET_VALID));
    // QUIC_VERSION_NEGOTIATION
    out.append(char(0x00));
    out.append(char(0x00));
    out.append(char(0x00));
    out.append(char(0x00));
    // mirror src CID as dst CID
    out.append(char(c.srcConnectionId.length()));
    out.append(c.srcConnectionId);
    // mirror dst CID as src CID
    out.append(char(c.dstConnectionId.length()));
    out.append(c.dstConnectionId);
    // request QUIC version 0x00000001
    out.append(char(0x00));
    out.append(char(0x00));
    out.append(char(0x00));
    out.append(char(0x01));

    if (comm_udp_sendto(listenConn->fd, c.clientAddress, out.rawContent(), out.length()) < 0) {
        xerrno = errno;
        debugs(94, 3, listenConn << " sendto: " << xstrerr(xerrno));
    } else {
        debugs(94, 2, "QUIC version negotiate with FD " << listenConn->fd << " remote=" << c.clientAddress);
    }
}

/// produce the unique ID for this QUIC connection
SBuf
Quic::Acceptor::clientCacheKey(ConnectionPointer &p) const
{
    SBuf key = p->srcConnectionId;
    key.append(p->dstConnectionId);
    char *buf = key.rawAppendStart(MAX_IPSTRLEN);
    auto len = p->clientAddress.toHostStr(buf, key.spaceSize());
    if (len > 0)
        key.rawAppendFinish(buf, len);
    return key;
}

