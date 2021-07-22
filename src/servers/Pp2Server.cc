/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "http/Stream.h"
#include "parser/BinaryTokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/Parser.h"
#include "servers/FtpServer.h"
#include "servers/Pp2Server.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(Pp2Server);

void
ProxyProtocol::OnClientAccept(const CommAcceptCbParams &params)
{
    AsyncJob::Start(new Pp2Server(params.port, params.conn));
}

Pp2Server::Pp2Server(const AnyP::PortCfgPointer &aPort, const Comm::ConnectionPointer &aClient) :
        AsyncJob("Pp2Server"),
        ::Server(aPort, aClient, nullptr, SBuf())
{
}

void
Pp2Server::start()
{
    // will close the connection on failure
    if (proxyProtocolValidateClient())
        readSomeData();
}

bool
Pp2Server::handleReadData()
{
    if (!parseProxyProtocolHeader()) {
        terminateAll(ERR_NONE, LogTagsErrors());
        return true;
    }

    stopReading();

    auto xact = MasterXaction::MakePortful(port);
    xact->tcpClient = clientConnection;
 
    ::Server *srv;
    switch (port->transport.protocol)
    {
    case AnyP::PROTO_HTTP:
        srv = Http::NewServer(xact);
        break;

    case AnyP::PROTO_HTTPS:
        srv = Https::NewServer(xact);
        break;

    case AnyP::PROTO_FTP:
        srv = new Ftp::Server(xact);
        break;

    default: // other protocols not supported yet
        mustStop("unsupported transfer protocol");
        return true;
    }
    srv->pp2Client = pp2Client;
    srv->inBuf = inBuf;

    clientConnection = nullptr; // passed control to 'srv'
    assert(doneAll());
    return false;
}

void
Pp2Server::terminateAll(const Error &error, const LogTagsErrors &)
{
    debugs(33, 3, "after " << error);
    if (!inBuf.isEmpty()) {
        debugs(33, 3, "forgetting client bytes: " << inBuf.length());
        inBuf.clear();
    }
    clientConnection->close();
}

void
Pp2Server::fillChecklist(ACLFilledChecklist &ch) const
{
    ch.my_addr = port->s;

    ch.fd(clientConnection->fd);
    ch.src_addr = clientConnection->remote;
    ch.dst_addr = clientConnection->local;
}

/**
 * Perform cleanup on PROXY protocol errors.
 * If header parsing hits a fatal error terminate the connection,
 * otherwise wait for more data.
 */
bool
Pp2Server::proxyProtocolError(const char *msg)
{
    if (msg) {
        // This is important to know, but maybe not so much that flooding the log is okay.
#if QUIET_PROXY_PROTOCOL
        // display the first of every 32 occurrences at level 1, the others at level 2.
        static uint8_t hide = 0;
        debugs(33, (hide++ % 32 == 0 ? DBG_IMPORTANT : 2), msg << " from " << clientConnection);
#else
        debugs(33, DBG_IMPORTANT, msg << " from " << clientConnection);
#endif
        mustStop(msg);
    }
    return false;
}

/**
 * Perform proxy_protocol_access ACL tests on the client which
 * connected to PROXY protocol port to see if we trust the
 * sender enough to accept their PROXY header claim.
 */
bool
Pp2Server::proxyProtocolValidateClient()
{
    if (!Config.accessList.proxyProtocol)
        return proxyProtocolError("PROXY client not permitted by default ACL");

    ACLFilledChecklist ch(Config.accessList.proxyProtocol, nullptr);
    fillChecklist(ch);
    if (!ch.fastCheck().allowed())
        return proxyProtocolError("PROXY client not permitted by ACLs");

    return true;
}

/// Attempts to extract a PROXY protocol header from the input buffer and,
/// upon success, initiates the nested protocol ::Server
/// \returns true if the header was successfully parsed
/// \returns false if more data is needed to parse the header or on error
bool
Pp2Server::parseProxyProtocolHeader()
{
    try {
        const auto parsed = ProxyProtocol::Parse(inBuf);
        pp2Client = parsed.header;
        assert(bool(pp2Client));
        inBuf.consume(parsed.size);
        if (pp2Client->hasForwardedAddresses()) {
            clientConnection->local = pp2Client->destinationAddress;
            clientConnection->remote = pp2Client->sourceAddress;
            if ((clientConnection->flags & COMM_TRANSPARENT))
                clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
            debugs(33, 5, "PROXY/" << pp2Client->version() << " upgrade: " << clientConnection);
        }
    } catch (const Parser::BinaryTokenizer::InsufficientInput &) {
        debugs(33, 3, "PROXY protocol: waiting for more than " << inBuf.length() << " bytes");
        return false;
    } catch (const std::exception &e) {
        return proxyProtocolError(e.what());
    }
    return true;
}

