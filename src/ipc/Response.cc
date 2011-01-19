/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "ipc/Response.h"
#include "ipc/TypedMsgHdr.h"


std::ostream& Ipc::operator << (std::ostream &os, const Response& response)
{
    os << "[response.requestId %u]" << response.requestId << '}';
    return os;
}
