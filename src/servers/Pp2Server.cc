/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "http/Stream.h"
#include "parser/BinaryTokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/Parser.h"
#include "servers/Pp2Server.h"
#include "SquidConfig.h"

void
Pp2Server::start()
{
    if (!proxyProtocolValidateClient()) // will close the connection on failure
        return;

    readSomeData();
}

bool
Pp2Server::handleReadData()
{
    if (!parseProxyProtocolHeader()) {
        terminateAll(ERR_NONE, LogTagsErrors());
        return true;
    }

    xaction->preservedClientData = inBuf; // may be empty

    // TODO: initiate child Server for port
    // on errors: terminate this Job + connection, and return true

    // TODO: end this Job as successful and return false
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
    // TODO copy details from xaction to ch
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
/// upon success, stores the parsed header in MasterXaction::pp2Client
/// \returns true if the header was successfully parsed
/// \returns false if more data is needed to parse the header or on error
bool
Pp2Server::parseProxyProtocolHeader()
{
    try {
        const auto parsed = ProxyProtocol::Parse(inBuf);
        xaction->pp2Client = parsed.header;
        assert(bool(xaction->pp2Client));
        inBuf.consume(parsed.size);
        if (xaction->pp2Client->hasForwardedAddresses()) {
            clientConnection->local = xaction->pp2Client->destinationAddress;
            clientConnection->remote = xaction->pp2Client->sourceAddress;
            if ((clientConnection->flags & COMM_TRANSPARENT))
                clientConnection->flags ^= COMM_TRANSPARENT; // prevent TPROXY spoofing of this new IP.
            debugs(33, 5, "PROXY/" << xaction->pp2Client->version() << " upgrade: " << clientConnection);
        }
    } catch (const Parser::BinaryTokenizer::InsufficientInput &) {
        debugs(33, 3, "PROXY protocol: waiting for more than " << inBuf.length() << " bytes");
        return false;
    } catch (const std::exception &e) {
        return proxyProtocolError(e.what());
    }
    return true;
}

