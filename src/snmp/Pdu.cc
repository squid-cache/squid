/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Pdu.h"
#include "snmp/Var.h"
#include "snmp_core.h"
#include "tools.h"

#include <algorithm>

Snmp::Pdu::Pdu()
{
    init();
}

Snmp::Pdu::Pdu(const Pdu& pdu)
{
    init();
    assign(pdu);
}

Snmp::Pdu::~Pdu()
{
    clear();
}

Snmp::Pdu&
Snmp::Pdu::operator = (const Pdu& pdu)
{
    clear();
    assign(pdu);
    return *this;
}

void
Snmp::Pdu::init()
{
    memset(static_cast<snmp_pdu *>(this), 0, sizeof(snmp_pdu));
    aggrCount = 0;
    errstat = SNMP_DEFAULT_ERRSTAT;
    errindex = SNMP_DEFAULT_ERRINDEX;
}

void
Snmp::Pdu::aggregate(const Pdu& pdu)
{
    Must(varCount() == pdu.varCount());
    ++aggrCount;
    for (variable_list* p_aggr = variables, *p_var = pdu.variables; p_var != nullptr;
            p_aggr = p_aggr->next_variable, p_var = p_var->next_variable) {
        Must(p_aggr != nullptr);
        Var& aggr = static_cast<Var&>(*p_aggr);
        Var& var = static_cast<Var&>(*p_var);
        if (aggr.isNull()) {
            aggr.setName(var.getName());
            aggr.copyValue(var);
        } else {
            switch (snmpAggrType(aggr.name, aggr.name_length)) {
            case atSum:
            case atAverage:
                // The mean-average division is done later
                // when the Snmp::Pdu::fixAggregate() called
                aggr += var;
                break;
            case atMax:
                if (var > aggr)
                    aggr.copyValue(var);
                break;
            case atMin:
                if (var < aggr)
                    aggr.copyValue(var);
                break;
            default:
                break;
            }
        }
    }
}

void
Snmp::Pdu::clear()
{
    clearSystemOid();
    clearVars();
    init();
}

void
Snmp::Pdu::assign(const Pdu& pdu)
{
// see https://github.com/net-snmp/net-snmp/blob/fb7534d9/include/net-snmp/types.h#L139-L247

    // Protocol-version independent fields
    version = pdu.version;
    command = pdu.command;
    reqid = pdu.reqid;
    msgid = pdu.msgid;
    transid = pdu.transid;
    sessid = pdu.sessid;
    errstat = pdu.errstat;
    errindex = pdu.errindex;
    time = pdu.time;
    flags = pdu.flags;
    securityModel = pdu.securityModel;
    securityLevel = pdu.securityLevel;
    msgParseModel = pdu.msgParseModel;
    msgMaxSize = pdu.msgMaxSize;

    // Transport-specific opaque data.
    transport_data = nullptr;
    if (pdu.transport_data_length > 0) {
        transport_data = new char[pdu.transport_data_length];
        memcpy(transport_data, pdu.transport_data, pdu.transport_data_length);
    }
    transport_data_length = pdu.transport_data_length;
    tDomain = pdu.tDomain;
    tDomainLen = pdu.tDomainLen;
    setVars(pdu.variables);

    // SNMPv1 & SNMPv2c fields
    community = reinterpret_cast<u_char*>(xstrndup(reinterpret_cast<const char*>(pdu.community), pdu.community_len));
    community_len = pdu.community_len;

    // Trap information
    setSystemOid(pdu.getSystemOid());
    trap_type = pdu.trap_type;
    specific_type = pdu.specific_type;
    memcpy(agent_addr, pdu.agent_addr, sizeof(pdu.agent_addr));

    // SNMPv3 fields - not supported yet
    // AgentX fields - not supported

    // Squid object members
    aggrCount = pdu.aggrCount;
}

void
Snmp::Pdu::clearVars()
{
    variable_list* var = variables;
    while (var != nullptr) {
        variable_list* tmp = var;
        var = var->next_variable;
        delete static_cast<Var*>(tmp);
    }
    variables = nullptr;
}

void
Snmp::Pdu::setVars(variable_list* vars)
{
    clearVars();
    for (variable_list** p_var = &variables; vars != nullptr;
            vars = vars->next_variable, p_var = &(*p_var)->next_variable) {
        *p_var = new Var(static_cast<Var&>(*vars));
    }
}

void
Snmp::Pdu::clearSystemOid()
{
    if (enterprise != nullptr) {
        xfree(enterprise);
        enterprise = nullptr;
    }
    enterprise_length = 0;
}

Range<const oid*>
Snmp::Pdu::getSystemOid() const
{
    return Range<const oid*>(enterprise, enterprise + enterprise_length);
}

void
Snmp::Pdu::setSystemOid(const Range<const oid*>& systemOid)
{
    clearSystemOid();
    if (systemOid.start != NULL && systemOid.size() != 0) {
        enterprise_length = systemOid.size();
        enterprise = static_cast<oid*>(xmalloc(enterprise_length * sizeof(oid)));
        std::copy(systemOid.start, systemOid.end, enterprise);
    }
}

void
Snmp::Pdu::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putPod(version);
    msg.putPod(command);
    msg.putPod(reqid);
    msg.putPod(msgid);
    msg.putPod(transid);
    msg.putPod(sessid);
    msg.putPod(errstat);
    msg.putPod(errindex);
    msg.putPod(time);
    msg.putPod(flags);
    msg.putPod(securityModel);
    msg.putPod(securityLevel);
    msg.putPod(msgParseModel);
    msg.putPod(msgMaxSize);
    msg.putInt(transport_data_length);
    if (transport_data_length > 0) {
        Must(transport_data != nullptr);
        msg.putFixed(transport_data, transport_data_length);
    }
    msg.putInt(enterprise_length);
    if (enterprise_length > 0) {
        Must(enterprise != nullptr);
        msg.putFixed(enterprise, enterprise_length * sizeof(oid));
    }
    msg.putInt(community_len);
    if (community_len > 0) {
        Must(community != nullptr);
        msg.putFixed(community, community_len);
    }
    msg.putPod(trap_type);
    msg.putPod(specific_type);
    msg.putPod(agent_addr);
    msg.putInt(varCount());
    for (variable_list* var = variables; var != nullptr; var = var->next_variable)
        static_cast<Var*>(var)->pack(msg);
}

void
Snmp::Pdu::unpack(const Ipc::TypedMsgHdr& msg)
{
    clear();
    msg.getPod(version);
    msg.getPod(command);
    msg.getPod(reqid);
    msg.getPod(msgid);
    msg.getPod(transid);
    msg.getPod(sessid);
    msg.getPod(errstat);
    msg.getPod(errindex);
    msg.getPod(time);
    msg.getPod(flags);
    msg.getPod(securityModel);
    msg.getPod(securityLevel);
    msg.getPod(msgParseModel);
    msg.getPod(msgMaxSize);
    transport_data_length = msg.getInt();
    if (transport_data_length > 0) {
        transport_data = static_cast<oid*>(xmalloc(transport_data_length));
        msg.getFixed(transport_data, transport_data_length);
    }
    enterprise_length = msg.getInt();
    if (enterprise_length > 0) {
        enterprise = static_cast<oid*>(xmalloc(enterprise_length * sizeof(oid)));
        msg.getFixed(enterprise, enterprise_length * sizeof(oid));
    }
    community_len = msg.getInt();
    if (community_len > 0) {
        community = static_cast<u_char*>(xmalloc(community_len));
        msg.getFixed(community, community_len);
    }
    msg.getPod(trap_type);
    msg.getPod(specific_type);
    msg.getPod(agent_addr);
    int count = msg.getInt();
    for (variable_list** p_var = &variables; count > 0;
            p_var = &(*p_var)->next_variable, --count) {
        Var* var = new Var();
        var->unpack(msg);
        *p_var = var;
    }
}

int
Snmp::Pdu::varCount() const
{
    int count = 0;
    for (variable_list* var = variables; var != nullptr; var = var->next_variable)
        ++count;
    return count;
}

void
Snmp::Pdu::fixAggregate()
{
    if (aggrCount < 2)
        return;
    for (variable_list* p_aggr = variables; p_aggr != nullptr; p_aggr = p_aggr->next_variable) {
        Var& aggr = static_cast<Var&>(*p_aggr);
        if (snmpAggrType(aggr.name, aggr.name_length) == atAverage) {
            aggr /= aggrCount;
        }
    }
    aggrCount = 0;
}

