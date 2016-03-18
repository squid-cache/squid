/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#ifndef SQUID_SNMP_AGENT_H_
#define SQUID_SNMP_AGENT_H_

#if SQUID_SNMP

#include "cache_snmp.h"
#include "snmp_vars.h"

variable_list *snmp_confFn(variable_list *, snint *);
variable_list *snmp_sysFn(variable_list *, snint *);
variable_list *snmp_prfSysFn(variable_list *, snint *);
variable_list *snmp_prfProtoFn(variable_list *, snint *);
variable_list *snmp_netIpFn(variable_list *, snint *);
variable_list *snmp_netFqdnFn(variable_list *, snint *);
variable_list *snmp_netDnsFn(variable_list *, snint *);
variable_list *snmp_meshPtblFn(variable_list *, snint *);
variable_list *snmp_meshCtblFn(variable_list *, snint *);

#endif /* SQUID_SNMP */
#endif /* SQUID_SNMP_AGENT_H_ */

