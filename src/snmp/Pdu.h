/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#ifndef SQUID_SNMPX_PDU_H
#define SQUID_SNMPX_PDU_H

#include "ipc/forward.h"
#include "Range.h"
#include "snmp.h"

namespace Snmp
{

/// snmp_pdu wrapper introduce the feature
/// to aggregate variables and to pack/unpack message
class Pdu: public snmp_pdu
{
public:
    Pdu();
    Pdu(const Pdu& pdu);
    Pdu& operator = (const Pdu& pdu);
    ~Pdu();

    void aggregate(const Pdu& pdu);
    void fixAggregate();
    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()
    void unpack(const Ipc::TypedMsgHdr& msg); ///< restore struct from the message
    int  varCount() const; ///< size of variables list
    void clear();  ///< clear all internal members
    void setVars(variable_list* vars); ///< perform assignment of variables list
    void clearVars(); ///< clear variables list
    Range<const oid*> getSystemOid() const;
    void setSystemOid(const Range<const oid*>& systemOid);
    void clearSystemOid();

private:
    void init(); ///< initialize members
    void assign(const Pdu& pdu); ///< perform full assignment
    unsigned int aggrCount = 0;  ///< The number of other Pdus merged into
};

} // namespace Snmp

#endif /* SQUID_SNMPX_PDU_H */

