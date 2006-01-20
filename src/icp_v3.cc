
/*
 * $Id: icp_v3.cc,v 1.40 2006/01/19 18:40:28 wessels Exp $
 *
 * DEBUG: section 12    Internet Cache Protocol
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Store.h"
#include "ICP.h"
#include "HttpRequest.h"

class ICP3State : public ICPState, public StoreClient
{

public:
    ICP3State(icp_common_t &aHeader):ICPState(aHeader){}

    ~ICP3State();
    void created (StoreEntry *newEntry);
};

static void

doV3Query(int fd, struct sockaddr_in from, char *buf, icp_common_t header)
{
    /* We have a valid packet */
    char *url = buf + sizeof(icp_common_t) + sizeof(u_int32_t);
    HttpRequest *icp_request = icpGetRequest (url, header.reqnum, fd, &from);

    if (!icp_request)
        return;

    if (!icpAccessAllowed(&from, icp_request))
    {
        icpDenyAccess (&from, url, header.reqnum, fd);
        delete icp_request;
        return;
    }

    /* The peer is allowed to use this cache */
    ICP3State *state = new ICP3State (header);

    state->request = icp_request;

    state->fd = fd;

    state->from = from;

    state->url = xstrdup (url);

    StoreEntry::getPublic (state, url, METHOD_GET);
}

ICP3State::~ICP3State ()
{}

void
ICP3State::created (StoreEntry *newEntry)
{
    StoreEntry *entry = newEntry->isNull () ? NULL : newEntry;
    debug(12, 5) ("icpHandleIcpV3: OPCODE %s\n",
                  icp_opcode_str[header.opcode]);
    icp_opcode codeToSend;

    if (icpCheckUdpHit(entry, request)) {
        codeToSend = ICP_HIT;
    } else if (icpGetCommonOpcode() == ICP_ERR)
        codeToSend = ICP_MISS;
    else
        codeToSend = icpGetCommonOpcode();

    icpCreateAndSend (codeToSend, 0, url, header.reqnum, 0, fd, &from);

    delete this;
}

/* Currently Harvest cached-2.x uses ICP_VERSION_3 */
void

icpHandleIcpV3(int fd, struct sockaddr_in from, char *buf, int len)
{
    if (len <= 0)
    {
        debug(12, 3) ("icpHandleIcpV3: ICP message is too small\n");
        return;
    }

    icp_common_t header (buf, len);
    /*
     * Length field should match the number of bytes read
     */

    if (len != header.length)
    {
        debug(12, 3) ("icpHandleIcpV3: ICP message is too small\n");
        return;
    }

    switch (header.opcode)
    {

    case ICP_QUERY:
        doV3Query(fd, from,buf, header);
        break;

    case ICP_HIT:
#if ALLOW_SOURCE_PING

    case ICP_SECHO:
#endif

    case ICP_DECHO:

    case ICP_MISS:

    case ICP_DENIED:

    case ICP_MISS_NOFETCH:
        header.handleReply(buf, &from);
        break;

    case ICP_INVALID:

    case ICP_ERR:
        break;

    default:
        debug(12, 0) ("icpHandleIcpV3: UNKNOWN OPCODE: %d from %s\n",
                      header.opcode, inet_ntoa(from.sin_addr));
        break;
    }
}
