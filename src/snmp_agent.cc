#include "squid.h"

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_vars.h"
#include "snmp_oidlist.h"
#include "cache_snmp.h"

#include "mib.h"

enum {
    HTTP_SVC, ICP_SVC, DNS_SVC
};

static struct snmp_pdu *snmp_agent_response(struct snmp_pdu *PDU);
struct snmp_session *Session;
extern StatCounters *CountHist;
extern int get_median_svc(int, int);

/* returns: 
 * 2: no such object in this mib
 * 1: ok
 * 0: failed */

int
snmp_agent_parse(u_char * buf, int len, u_char * outbuf, int *outlen,
    u_long from_addr, long *this_reqid)
{
    struct snmp_pdu *PDU, *RespPDU;
    u_char *Community;
    int ret;
    /* Now that we have the data, turn it into a PDU */
    PDU = snmp_pdu_create(0);
    Community = snmp_parse(Session, PDU, buf, len);
    if (Community == NULL) {
	debug(49, 8) ("snmp_agent_parse: Community == NULL\n");

	snmp_free_pdu(PDU);
	return 0;
    }
#if 0
    if (!community_check(Community)) {
	xfree(Community);
	/* Wrong community! XXXXX */
    }
#endif

    xfree(Community);
    debug(49, 5) ("snmp_agent_parse: reqid=%d\n", PDU->reqid);
    RespPDU = snmp_agent_response(PDU);
    snmp_free_pdu(PDU);
    if (RespPDU == NULL) {
	debug(49, 8) ("snmp_agent_parse: RespPDU == NULL\n");
	return 2;
    }
    debug(49, 8) ("snmp_agent_parse: Response pdu (%x) errstat=%d reqid=%d.\n",
	RespPDU, RespPDU->errstat, RespPDU->reqid);
#if 0
    if (RespPDU->variables) {
	debug(49, 8) ("snmp_agent_parse: len=%d\n", RespPDU->variables->val_len);
    }
#endif
    /* Encode it */
    ret = snmp_build(Session, RespPDU, outbuf, outlen);
    /* XXXXX Handle failure */
    snmp_free_pdu(RespPDU);
    return 1;
}



static struct snmp_pdu *
snmp_agent_response(struct snmp_pdu *PDU)
{
    struct snmp_pdu *Answer = NULL;
    variable_list *VarPtr, *VarNew = NULL;
    variable_list **VarPtrP, **RespVars;
    int index = 0;
    oid_ParseFn *ParseFn;

    debug(49, 9) ("Received a %d PDU\n", PDU->command);

    /* Create a response */
    Answer = snmp_pdu_create(SNMP_PDU_RESPONSE);
    if (Answer == NULL)
	return (NULL);
    Answer->reqid = PDU->reqid;
    Answer->errindex = 0;

    if (PDU->command == SNMP_PDU_GET) {

	RespVars = &(Answer->variables);
	/* Loop through all variables */
	for (VarPtrP = &(PDU->variables);
	    *VarPtrP;
	    VarPtrP = &((*VarPtrP)->next_variable)) {
	    VarPtr = *VarPtrP;

	    index++;

	    /* Find the parsing function for this variable */
	    ParseFn = oidlist_Find(VarPtr->name, VarPtr->name_length);

	    if (ParseFn == NULL) {
		Answer->errstat = SNMP_ERR_NOSUCHNAME;
		debug(49, 5) ("snmp_agent_response: No such oid. ");
	    } else
		VarNew = (*ParseFn) (VarPtr, (long *) &(Answer->errstat));

	    /* Was there an error? */
	    if ((Answer->errstat != SNMP_ERR_NOERROR) ||
		(VarNew == NULL)) {
		Answer->errindex = index;
		debug(49, 5) ("snmp_agent_parse: successful.\n");
		/* Just copy the rest of the variables.  Quickly. */
		*RespVars = VarPtr;
		*VarPtrP = NULL;
		return (Answer);
	    }
	    /* No error.  Insert this var at the end, and move on to the next.
	     */
	    *RespVars = VarNew;
	    RespVars = &(VarNew->next_variable);
	}

	return (Answer);
    } else if (PDU->command == SNMP_PDU_GETNEXT) {
	oid *TmpOidName;
	int TmpOidNameLen = 0;

	/* Find the next OID. */
	VarPtr = PDU->variables;

	ParseFn = oidlist_Next(VarPtr->name, VarPtr->name_length,
	    &(TmpOidName), (long *) &(TmpOidNameLen));

	if (ParseFn == NULL) {
	    Answer->errstat = SNMP_ERR_NOSUCHNAME;
	    debug(49, 9) ("No such oid: ");
	    print_oid(VarPtr->name, VarPtr->name_length);
	} else {
	    xfree(VarPtr->name);
	    VarPtr->name = TmpOidName;
	    VarPtr->name_length = TmpOidNameLen;
	    VarNew = (*ParseFn) (VarPtr, (long *) &(Answer->errstat));
	}

	/* Was there an error? */
	if (Answer->errstat != SNMP_ERR_NOERROR) {
	    Answer->errindex = 1;

	    /* Just copy this variable */
	    Answer->variables = VarPtr;
	    PDU->variables = NULL;
	} else {
	    Answer->variables = VarNew;
	}

	/* Done.  Return this PDU */
	return (Answer);
    }				/* end SNMP_PDU_GETNEXT */
#
    debug(49, 9) ("Ignoring PDU %d\n", PDU->command);
    snmp_free_pdu(Answer);
    return (NULL);
}

char private_community[] = "public";

int
community_check(char *b)
{
    return (!strcmp(b, private_community));
}

int
init_agent_auth()
{
    Session = (struct snmp_session *) xmalloc(sizeof(struct snmp_session));
    if (Session == NULL) {
	perror("malloc");
	return 3;
    }
    Session->Version = SNMP_VERSION_1;
    Session->authenticator = NULL;
    Session->community = (u_char *) xstrdup("public");
    Session->community_len = 6;
    return 1;
}

/************************************************************************

 SQUID MIB Implementation

 ************************************************************************/

variable_list *
snmp_basicFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    char *pp;

    debug(49, 5) ("snmp_basicFn: Processing request with magic %d!\n", Var->name[7]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[7]) {
    case VERSION_DESCR:
    case VERSION_ID:
	pp = SQUID_VERSION;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case UPTIME:
    case SYSORLASTCHANGE:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = tvSubDsec(squid_start, current_time);
	break;
    case SYSCONTACT:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(Config.adminEmail);
	Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
    case SYSYSNAME:
	if ((pp = Config.visibleHostname) == NULL)
	    pp = (char *) getMyHostname();
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case SYSLOCATION:
	pp = "Cyberspace";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case SYSSERVICES:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = 72;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    debug(49, 5) ("snmp_basicFn: Done. returning a real value!\n");

    return (Answer);
}

variable_list *
snmp_sysFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    static fde *f = NULL;
    int num = 1, cnt = 0;
    static struct in_addr addr;
    static long long_return;

    debug(49, 5) ("snmp_sysFn: Processing request with magic %d: \n", Var->name[8]);
    print_oid(Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[8]) {
    case SYSVMSIZ:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = store_mem_size;
	break;
    case SYSSTOR:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = store_swap_size;
	break;
    case SYSFDTBL:
	num = Var->name[11];
	debug(49, 9) ("snmp_sysFn: num=%d\n", num);
	while (num && cnt < Squid_MaxFD) {
	    f = &fd_table[cnt++];
	    if (!f->open)
		continue;
	    num--;
	}
	if (num != 0 || !f) {
	    debug(49, 9) ("snmp_sysFn: no such name. %x\n", f);
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	switch (Var->name[10]) {
	case SYS_FD_NUMBER:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = Var->name[11];
	    break;
	case SYS_FD_TYPE:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = f->type;
	    break;
	case SYS_FD_TOUT:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) (f->timeout_handler ? (f->timeout - squid_curtime) / 60 : 0);
	    break;
	case SYS_FD_NREAD:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) f->bytes_read;
	    break;
	case SYS_FD_NWRITE:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) f->bytes_written;
	    break;
	case SYS_FD_ADDR:
	    if (f->type != FD_SOCKET)
		long_return = (long) 0;
	    else {
		safe_inet_addr(f->ipaddr, &addr);
		long_return = (long) addr.s_addr;
	    }
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = SMI_IPADDRESS;
	    *(Answer->val.integer) = (long) long_return;
	    break;
	case SYS_FD_NAME:
	    Answer->type = ASN_OCTET_STR;
	    Answer->val_len = strlen(f->desc);
	    Answer->val.string = (u_char *) xstrdup(f->desc);
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    debug(49, 5) ("snmp_sysFn: Done. returning a real value!\n");
    return Answer;
}

variable_list *
snmp_confFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    char *cp = NULL;

    debug(49, 5) ("snmp_confFn: Processing request with magic %d!\n", Var->name[8]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[8]) {
    case CONF_ADMIN:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(Config.adminEmail);
	Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
	break;
    case CONF_UPTIME:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = tvSubDsec(squid_start, current_time);
	break;
    case CONF_STORAGE:
	switch (Var->name[9]) {
	case CONF_ST_MMAXSZ:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Mem.maxSize;
	    break;
	case CONF_ST_MHIWM:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Mem.highWaterMark;
	    break;
	case CONF_ST_MLOWM:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Mem.lowWaterMark;
	    break;
	case CONF_ST_SWMAXSZ:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Swap.maxSize;
	    break;
	case CONF_ST_SWHIWM:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Swap.highWaterMark;
	    break;
	case CONF_ST_SWLOWM:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Swap.lowWaterMark;
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	break;
    case CONF_WAIS_RHOST:
	if (Config.Wais.relayHost)
	    cp = Config.Wais.relayHost;
	else
	    cp = "None";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(cp);
	Answer->val.string = (u_char *) xstrdup(cp);
	break;
    case CONF_WAIS_RPORT:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) Config.Wais.relayPort;
	break;
    case CONF_TIO:
	switch (Var->name[9]) {
	case CONF_TIO_RD:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Timeout.read;
	    break;
	case CONF_TIO_CON:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Timeout.connect;
	    break;
	case CONF_TIO_REQ:
	    Answer->val_len = sizeof(long);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) Config.Timeout.request;
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
    case CONF_LOG_LVL:
	if (!(cp = Config.debugOptions))
	    cp = "None";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(cp);
	Answer->val.string = (u_char *) xstrdup(cp);
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_confPtblFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    char *cp = NULL;
    peer *p = NULL;
    int cnt;
    debug(49, 5) ("snmp_confPtblFn: peer %d requested!\n", Var->name[11]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    p = Config.peers;
    cnt = Var->name[11];
    debug(49, 5) ("snmp_confPtblFn: we want .x.%d\n", Var->name[10]);
    while (--cnt)
	if (!(p = p->next));
    if (p == NULL) {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    switch (Var->name[10]) {
    case CONF_PTBL_ID:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) Var->name[10];
	break;
    case CONF_PTBL_NAME:
	cp = p->host;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(cp);
	Answer->val.string = (u_char *) xstrdup(cp);
	break;
    case CONF_PTBL_IP:
	Answer->type = SMI_IPADDRESS;
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->val_len = sizeof(long);
	*(Answer->val.integer) = (long) (p->in_addr.sin_addr.s_addr);
	break;
    case CONF_PTBL_HTTP:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) p->http_port;
	break;
    case CONF_PTBL_ICP:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) p->icp_port;
	break;
    case CONF_PTBL_TYPE:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) p->type;
	break;
    case CONF_PTBL_STATE:
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (long) neighborUp(p);
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_prfSysFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    static struct rusage rusage;

    debug(49, 5) ("snmp_prfSysFn: Processing request with magic %d!\n", Var->name[9]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(long);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = ASN_INTEGER;

    switch (Var->name[9]) {
    case PERF_SYS_PF:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = rusage_pagefaults(&rusage);
	break;
    case PERF_SYS_NUMR:
	*(Answer->val.integer) = IOStats.Http.reads;
	break;
    case PERF_SYS_DEFR:
	*(Answer->val.integer) = IOStats.Http.reads_deferred;
	break;
    case PERF_SYS_MEMUSAGE:
	*(Answer->val.integer) = (long) statMemoryAccounted() >> 10;
	break;
    case PERF_SYS_CPUUSAGE:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = (long) rusage_cputime(&rusage);
	break;
    case PERF_SYS_MAXRESSZ:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = (long) rusage_maxrss(&rusage);
	break;
    case PERF_SYS_CURLRUEXP:
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (long) ((double) storeExpiredReferenceAge() / 86400.0);
	break;
    case PERF_SYS_CURUNLREQ:
	*(Answer->val.integer) = (long) Counter.unlink.requests;
	break;
    case PERF_SYS_CURUNUSED_FD:
	*(Answer->val.integer) = (long) Squid_MaxFD - Number_FD;
	break;
    case PERF_SYS_CURRESERVED_FD:
	*(Answer->val.integer) = (long) Number_FD;
	break;
    case PERF_SYS_NUMOBJCNT:
	*(Answer->val.integer) = (long) memInUse(MEM_STOREENTRY);
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_prfPeerFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    peer *p = NULL;
    int cnt;
    debug(49, 5) ("snmp_prfPeerFn: Processing request with magic %d!\n", Var->name[9]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    p = Config.peers;
    cnt = Var->name[12];
    debug(49, 5) ("snmp_prfPeerFn: we want .%d.%d\n", Var->name[11], cnt);
    while (--cnt)
	if (!(p = p->next));
    if (p == NULL) {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    Answer->type = SMI_COUNTER32;
    Answer->val_len = sizeof(long);
    Answer->val.integer = xmalloc(Answer->val_len);

    switch (Var->name[11]) {
    case PERF_PEERSTAT_ID:
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = Var->name[11];
	break;
    case PERF_PEERSTAT_SENT:
	*(Answer->val.integer) = p->stats.pings_sent;
	break;
    case PERF_PEERSTAT_PACKED:
	*(Answer->val.integer) = p->stats.pings_acked;
	break;
    case PERF_PEERSTAT_FETCHES:
	*(Answer->val.integer) = p->stats.fetches;
	break;
    case PERF_PEERSTAT_RTT:
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = p->stats.rtt;
	break;
    case PERF_PEERSTAT_IGN:
	*(Answer->val.integer) = p->stats.ignored_replies;
	break;
    case PERF_PEERSTAT_KEEPAL_S:
	*(Answer->val.integer) = p->stats.n_keepalives_sent;
	break;
    case PERF_PEERSTAT_KEEPAL_R:
	*(Answer->val.integer) = p->stats.n_keepalives_recv;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	xfree(Answer->val.integer);
	return (NULL);
    }
    return Answer;
}


variable_list *
snmp_prfProtoFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;

    debug(49, 5) ("snmp_prfProtoFn: Processing request with magic %d!\n", Var->name[8]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    if (Var->name[9] == 1) {	/* cacheProtoAggregateStats */
	Answer->type = SMI_COUNTER32;
	Answer->val_len = sizeof(long);
	Answer->val.integer = xmalloc(Answer->val_len);
	switch (Var->name[10]) {
	case PERF_PROTOSTAT_AGGR_HTTP_REQ:
	    *(Answer->val.integer) = (long) Counter.client_http.requests;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_HITS:
	    *(Answer->val.integer) = (long) Counter.client_http.hits;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_ERRORS:
	    *(Answer->val.integer) = (long) Counter.client_http.errors;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_S:
	    *(Answer->val.integer) = (long) Counter.icp.pkts_sent;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_R:
	    *(Answer->val.integer) = (long) Counter.icp.pkts_recv;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_SKB:
	    *(Answer->val.integer) = (long) Counter.icp.kbytes_sent.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_RKB:
	    *(Answer->val.integer) = (long) Counter.icp.kbytes_recv.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_KBYTES_IN:
	    *(Answer->val.integer) = (long) Counter.client_http.kbytes_in.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_KBYTES_OUT:
	    *(Answer->val.integer) = (long) Counter.client_http.kbytes_out.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_CURSWAP:
	    *(Answer->val.integer) = (long) store_swap_size;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_SVC_5:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(5, HTTP_SVC);
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_SVC_5:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(5, ICP_SVC);
	    break;
	case PERF_PROTOSTAT_AGGR_DNS_SVC_5:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(5, DNS_SVC);
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_SVC_60:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(60, HTTP_SVC);
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_SVC_60:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(60, ICP_SVC);
	    break;
	case PERF_PROTOSTAT_AGGR_DNS_SVC_60:
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (long) get_median_svc(60, DNS_SVC);
	    break;
	default:
	    xfree(Answer->val.integer);
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
    } else {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}


variable_list *
snmp_dnsFn(variable_list * Var, long *ErrP)
{
    debug(49, 5) ("snmp_dnsFn: Processing request with magic %d!\n", Var->name[9]);
    if (Var->name[9] == NET_DNS_IPCACHE)
	return snmp_ipcacheFn(Var, ErrP);
    if (Var->name[9] == NET_DNS_FQDNCACHE)
	return snmp_fqdncacheFn(Var, ErrP);

    return NULL;
}
