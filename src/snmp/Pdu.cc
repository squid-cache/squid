/*
 * DEBUG: section 49    SNMP Interface
 *
 */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp_core.h"
#include "snmp/Pdu.h"
#include "snmp/Var.h"
#include "tools.h"
#if HAVE_ALGORITHM
#include <algorithm>
#endif

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
    memset(this, 0, sizeof(*this));
    errstat = SNMP_DEFAULT_ERRSTAT;
    errindex = SNMP_DEFAULT_ERRINDEX;
}

void
Snmp::Pdu::aggregate(const Pdu& pdu)
{
    Must(varCount() == pdu.varCount());
    ++aggrCount;
    for (variable_list* p_aggr = variables, *p_var = pdu.variables; p_var != NULL;
            p_aggr = p_aggr->next_variable, p_var = p_var->next_variable) {
        Must(p_aggr != NULL);
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
    command = pdu.command;
    address.sin_addr.s_addr = pdu.address.sin_addr.s_addr;
    reqid = pdu.reqid;
    errstat = pdu.errstat;
    errindex = pdu.errindex;
    non_repeaters = pdu.non_repeaters;
    max_repetitions = pdu.max_repetitions;
    agent_addr.sin_addr.s_addr = pdu.agent_addr.sin_addr.s_addr;
    trap_type = pdu.trap_type;
    specific_type = pdu.specific_type;
    time = pdu.time;
    aggrCount = pdu.aggrCount;
    setSystemOid(pdu.getSystemOid());
    setVars(pdu.variables);
}

void
Snmp::Pdu::clearVars()
{
    variable_list* var = variables;
    while (var != NULL) {
        variable_list* tmp = var;
        var = var->next_variable;
        snmp_var_free(tmp);
    }
    variables = NULL;
}

void
Snmp::Pdu::setVars(variable_list* vars)
{
    clearVars();
    for (variable_list** p_var = &variables; vars != NULL;
            vars = vars->next_variable, p_var = &(*p_var)->next_variable) {
        *p_var = new Var(static_cast<Var&>(*vars));
    }
}

void
Snmp::Pdu::clearSystemOid()
{
    if (enterprise != NULL) {
        xfree(enterprise);
        enterprise = NULL;
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
    msg.putPod(command);
    msg.putPod(address);
    msg.putPod(reqid);
    msg.putPod(errstat);
    msg.putPod(errindex);
    msg.putPod(non_repeaters);
    msg.putPod(max_repetitions);
    msg.putInt(enterprise_length);
    if (enterprise_length > 0) {
        Must(enterprise != NULL);
        msg.putFixed(enterprise, enterprise_length * sizeof(oid));
    }
    msg.putPod(agent_addr);
    msg.putPod(trap_type);
    msg.putPod(specific_type);
    msg.putPod(time);
    msg.putInt(varCount());
    for (variable_list* var = variables; var != NULL; var = var->next_variable)
        static_cast<Var*>(var)->pack(msg);
}

void
Snmp::Pdu::unpack(const Ipc::TypedMsgHdr& msg)
{
    clear();
    msg.getPod(command);
    msg.getPod(address);
    msg.getPod(reqid);
    msg.getPod(errstat);
    msg.getPod(errindex);
    msg.getPod(non_repeaters);
    msg.getPod(max_repetitions);
    enterprise_length = msg.getInt();
    if (enterprise_length > 0) {
        enterprise = static_cast<oid*>(xmalloc(enterprise_length * sizeof(oid)));
        msg.getFixed(enterprise, enterprise_length * sizeof(oid));
    }
    msg.getPod(agent_addr);
    msg.getPod(trap_type);
    msg.getPod(specific_type);
    msg.getPod(time);
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
    for (variable_list* var = variables; var != NULL; var = var->next_variable)
        ++count;
    return count;
}

void
Snmp::Pdu::fixAggregate()
{
    if (aggrCount < 2)
        return;
    for (variable_list* p_aggr = variables; p_aggr != NULL; p_aggr = p_aggr->next_variable) {
        Var& aggr = static_cast<Var&>(*p_aggr);
        if (snmpAggrType(aggr.name, aggr.name_length) == atAverage) {
            aggr /= aggrCount;
        }
    }
    aggrCount = 0;
}
