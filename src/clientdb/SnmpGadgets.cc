/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Client Database */

#include "squid.h"

#if SQUID_SNMP

#include "clientdb/Cache.h"
#include "clientdb/SnmpGadgets.h"
#include "MemBuf.h"
#include "snmp_core.h"

const Ip::Address *
client_entry(const Ip::Address *current)
{
    if (ClientDb::Cache.empty())
        return nullptr;

    if (current) {
        auto itr = ClientDb::Cache.find(*current);
        ++itr;
        if (itr == ClientDb::Cache.end())
            return nullptr;
        return &(itr->first);
    }

    return &(ClientDb::Cache.begin()->first);
}

variable_list *
snmp_meshCtblFn(variable_list * Var, snint * ErrP)
{
    Ip::Address keyIp;

    *ErrP = SNMP_ERR_NOERROR;
    MemBuf tmp;
    debugs(49, 6, HERE << "Current : length=" << Var->name_length << ": " << snmpDebugOid(Var->name, Var->name_length, tmp));
    if (Var->name_length == 16) {
        oid2addr(&(Var->name[12]), keyIp, 4);
    } else if (Var->name_length == 28) {
        oid2addr(&(Var->name[12]), keyIp, 16);
    } else {
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return NULL;
    }

    debugs(49, 5, "[" << keyIp << "] requested!");
    const auto c = ClientDb::Get(keyIp);
    if (!c) {
        debugs(49, 5, HERE << "not found.");
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return NULL;
    }

    variable_list *Answer = NULL;
    int aggr = 0;

    switch (Var->name[LEN_SQ_NET + 2]) {

    case MESH_CTBL_ADDR_TYPE: {
        int ival;
        ival = c->addr.isIPv4() ? INETADDRESSTYPE_IPV4 : INETADDRESSTYPE_IPV6 ;
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      ival, SMI_INTEGER);
    }
    break;

    case MESH_CTBL_ADDR: {
        Answer = snmp_var_new(Var->name, Var->name_length);
        // InetAddress doesn't have its own ASN.1 type,
        // like IpAddr does (SMI_IPADDRESS)
        // See: rfc4001.txt
        Answer->type = ASN_OCTET_STR;
        char client[MAX_IPSTRLEN];
        c->addr.toStr(client,MAX_IPSTRLEN);
        Answer->val_len = strlen(client);
        Answer->val.string =  (u_char *) xstrdup(client);
    }
    break;
    case MESH_CTBL_HTBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTREQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.n_requests,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTHITS:
        aggr = 0;

        for (LogTags_ot l = LOG_TAG_NONE; l < LOG_TYPE_MAX; ++l) {
            if (LogTags(l).isTcpHit())
                aggr += c->Http.result_hist[l];
        }

        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) aggr,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_HTHITBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Http.hit_kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPREQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.n_requests,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPHITS:
        aggr = c->Icp.result_hist[LOG_UDP_HIT];
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) aggr,
                                      SMI_COUNTER32);
        break;

    case MESH_CTBL_ICPHITBYTES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) c->Icp.hit_kbytes_out.kb,
                                      SMI_COUNTER32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        debugs(49, 5, "snmp_meshCtblFn: illegal column.");
        break;
    }

    return Answer;
}

#endif /*SQUID_SNMP */

