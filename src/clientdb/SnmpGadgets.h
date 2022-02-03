/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Client Database */

#ifndef _SQUID__SRC_CLIENTDB_SNMPGADGETS_H
#define _SQUID__SRC_CLIENTDB_SNMPGADGETS_H

#if SQUID_SNMP

#include "ip/Address.h"
#include "cache_snmp.h"
#include "snmp_vars.h"

/* AYJ 2021-12-20:
 * take one step across the ClientDb cache map/hash from the given IP.
 * If the cache entries have been changed between calls this will
 * produce unexpected results;
 * - all changes to the hash/map before 'current' will be skipped.
 * - not finding 'current' will skip to the end and produce nullptr.
 * XXX: use a better indexing mechanism for SNMP tables.
 */
const Ip::Address *client_entry(const Ip::Address *current);

/// produce the SNMP version of Client CB table
variable_list *snmp_meshCtblFn(variable_list *, snint *);

#endif /* USE_SNMP */
#endif /* _SQUID__SRC_CLIENTDB_SNMPGADGETS_H */
