
/*
 * $Id: dns.cc,v 1.70 1998/10/19 17:48:26 wessels Exp $
 *
 * DEBUG: section 34    Dnsserver interface
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

static helper *dnsservers = NULL;

static void
dnsStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Dnsserver Statistics:\n");
    helperStats(sentry, dnsservers);
}

void
dnsInit(void)
{
    static int init = 0;
    wordlist *w;
    if (!Config.Program.dnsserver)
	return;
    if (dnsservers == NULL)
    	dnsservers = helperCreate("dnsserver");
    dnsservers->n_to_start = Config.dnsChildren;
    dnsservers->ipc_type = IPC_TCP_SOCKET;
    assert(dnsservers->cmdline == NULL);
    wordlistAdd(&dnsservers->cmdline, Config.Program.dnsserver);
    if (Config.onoff.res_defnames)
	wordlistAdd(&dnsservers->cmdline, "-D");
    if (Config.dns_nameservers) {
	wordlistAdd(&dnsservers->cmdline, "-s");
	for (w = Config.dns_nameservers; w != NULL; w = w->next)
	    wordlistAdd(&dnsservers->cmdline, w->key);
    }
    helperOpenServers(dnsservers);
    if (!init) {
	cachemgrRegister("dns",
	    "Dnsserver Statistics",
	    dnsStats, 0, 1);
    }
    init++;
}

void
dnsShutdown(void)
{
    if (!dnsservers)
	return;
    helperShutdown(dnsservers);
    wordlistDestroy(&dnsservers->cmdline);
    if (!shutting_down)
	return;
    helperFree(dnsservers);
    dnsservers = NULL;
}

void
dnsSubmit(const char *lookup, HLPCB * callback, void *data)
{
    char buf[256];
    snprintf(buf, 256, "%s\n", lookup);
    helperSubmit(dnsservers, buf, callback, data);
}

#ifdef SQUID_SNMP
/*
 * The function to return the DNS via SNMP
 */
variable_list *
snmp_netDnsFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    debug(49, 5) ("snmp_netDnsFn: Processing request:\n", Var->name[LEN_SQ_NET +
	    1]);
    snmpDebugOid(5, Var->name, Var->name_length);
    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = SMI_COUNTER32;
    switch (Var->name[LEN_SQ_NET + 1]) {
    case DNS_REQ:
	*(Answer->val.integer) = dnsservers->stats.requests;
	break;
    case DNS_REP:
	*(Answer->val.integer) = dnsservers->stats.replies;
	break;
    case DNS_SERVERS:
	*(Answer->val.integer) = dnsservers->n_running;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}
#endif /*SQUID_SNMP */
