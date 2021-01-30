/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 12    Internet Cache Protocol (ICP) */

/**
 \defgroup ServerProtocolICPInternal3 ICPv3 Internals
 \ingroup ServerProtocolICPAPI
 */

#include "squid.h"
#include "HttpRequest.h"
#include "ICP.h"
#include "Store.h"

/// \ingroup ServerProtocolICPInternal3
class ICP3State : public ICPState, public StoreClient
{

public:
    ICP3State(icp_common_t &aHeader, HttpRequest *aRequest) :
        ICPState(aHeader, aRequest) {}

    ~ICP3State();
    void created (StoreEntry *newEntry);
};

/// \ingroup ServerProtocolICPInternal3
static void
doV3Query(int fd, Ip::Address &from, char *buf, icp_common_t header)
{
    /* We have a valid packet */
    char *url = buf + sizeof(icp_common_t) + sizeof(uint32_t);
    HttpRequest *icp_request = icpGetRequest(url, header.reqnum, fd, from);

    if (!icp_request)
        return;

    if (!icpAccessAllowed(from, icp_request)) {
        icpDenyAccess (from, url, header.reqnum, fd);
        delete icp_request;
        return;
    }

    /* The peer is allowed to use this cache */
    ICP3State *state = new ICP3State (header, icp_request);
    state->fd = fd;
    state->from = from;
    state->url = xstrdup(url);

    StoreEntry::getPublic (state, url, Http::METHOD_GET);
}

ICP3State::~ICP3State()
{}

void
ICP3State::created(StoreEntry *newEntry)
{
    StoreEntry *entry = newEntry->isNull () ? NULL : newEntry;
    debugs(12, 5, "icpHandleIcpV3: OPCODE " << icp_opcode_str[header.opcode]);
    icp_opcode codeToSend;

    if (icpCheckUdpHit(entry, request)) {
        codeToSend = ICP_HIT;
    } else if (icpGetCommonOpcode() == ICP_ERR)
        codeToSend = ICP_MISS;
    else
        codeToSend = icpGetCommonOpcode();

    icpCreateAndSend (codeToSend, 0, url, header.reqnum, 0, fd, from);

    delete this;
}

/// \ingroup ServerProtocolICPInternal3
/* Currently Harvest cached-2.x uses ICP_VERSION_3 */
void
icpHandleIcpV3(int fd, Ip::Address &from, char *buf, int len)
{
    if (len <= 0) {
        debugs(12, 3, "icpHandleIcpV3: ICP message is too small");
        return;
    }

    icp_common_t header (buf, len);
    /*
     * Length field should match the number of bytes read
     */

    if (len != header.length) {
        debugs(12, 3, "icpHandleIcpV3: ICP message is too small");
        return;
    }

    switch (header.opcode) {

    case ICP_QUERY:
        doV3Query(fd, from, buf, header);
        break;

    case ICP_HIT:

    case ICP_DECHO:

    case ICP_MISS:

    case ICP_DENIED:

    case ICP_MISS_NOFETCH:
        header.handleReply(buf, from);
        break;

    case ICP_INVALID:

    case ICP_ERR:
        break;

    default:
        debugs(12, DBG_CRITICAL, "icpHandleIcpV3: UNKNOWN OPCODE: " << header.opcode << " from " << from);
        break;
    }
}

