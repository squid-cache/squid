/*
 * DEBUG: section 49    SNMP Interface
 *
 */

#ifndef SQUID_SNMPX_RESPONSE_H
#define SQUID_SNMPX_RESPONSE_H

#include "ipc/forward.h"
#include "ipc/Response.h"
#include "snmp/Pdu.h"
#include <ostream>

namespace Snmp
{

///
class Response: public Ipc::Response
{
public:
    Response(unsigned int aRequestId);
    explicit Response(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    /* Ipc::Response API */
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual Ipc::Response::Pointer clone() const;

private:
    Response(const Response& response);

public:
    Pdu pdu; ///< SNMP protocol data unit
};

std::ostream& operator << (std::ostream& os, const Response& response);

} // namespace Snmp

#endif /* SQUID_SNMPX_RESPONSE_H */
