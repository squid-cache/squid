/*
 * Simple Network Management Protocol (RFC 1067).
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include "squid.h"

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

#include "mib.h"

#include "snmp_groupvars.h"

void snmp_input();
void snmp_trap();
int create_identical();
int parse_var_op_list();

struct pbuf *definitelyGetBuf();
int get_community();

extern communityEntry *communities;
extern usecEntry *users;
extern viewEntry *views;
extern int maintenanceView;

/* these can't be global in a multi-process router */
u_char sid[SID_MAX_LEN + 1];
int sidlen;
u_char *packet_end;

struct snmp_session _session;
struct snmp_session *session = &_session;

u_char _agentID[12] =
{0};
u_long _agentBoots;
u_long _agentStartTime;
u_long _agentSize;


/* fwd: */
static int check_auth(struct snmp_session *, u_char *, int, u_char *, int, usecEntry **);
static int bulk_var_op_list(u_char *, int, u_char *, int, int, int, long *);
static int goodValue(u_char, int, u_char, int);
static void setVariable(u_char *, u_char, int, u_char *, int);
/* from usec.c: */
extern void increment_stat();
extern void create_report();
extern void md5Digest();
extern int parse_parameters();

int
init_agent_auth(void)
{
    char hostname[256];
    struct hostent *hp;
    FILE *f;
    /* comes from snmpd.c: */

    /* agentID is based on enterprise number and local IP address */
    /* not "settable, thus, if agentBoots=0xffffffff, then all keys should be changed */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
	fatal("snmpd: cannot get hostname");
	return -1;
    }
    if ((hp = gethostbyname(hostname)) == NULL) {
	fatal("snmpd: cannot determine local hostname");
	return -1;
    }
    _agentID[3] = 35;		/* BNR private enterprise number */
    xmemcpy(&_agentID[4], hp->h_addr, hp->h_length);

    if (Config.Snmp.agentInfo == NULL) {
	debug(49, 1) ("init_agent_auth: WARNING: Config.Snmp.agentInfo == NULL\n");
	return -1;
    }
    if ((f = fopen(Config.Snmp.agentInfo, "r+")) == NULL) {
	debug(49, 5) ("init_agent_auth: Agent not installed properly, cannot open '%s'\n",
	    Config.Snmp.agentInfo);
	debug(49, 5) ("init_agent_auth: Create a empty file '%s'. This is used for\n",
	    Config.Snmp.agentInfo);
	debug(49, 5) ("NV store of the agentBoots object.\n");
	return -1;
    }
    fscanf(f, "%ld", &_agentBoots);
    _agentBoots++;
    fseek(f, 0, 0);
    fprintf(f, "%ld\n", _agentBoots);
    fclose(f);


    _agentStartTime = -time(NULL);

    _agentSize = SNMP_MAX_LEN;

    return 0;
}

int
snmp_agent_parse(u_char *sn_data,
     int length,
     u_char *out_sn_data,
     int *out_length,
     u_long sourceip,		/* possibly for authentication */
     long *ireqid)
{
    u_char msgtype, type;
    long zero = 0;
    long reqid, errstat, errindex, dummyindex;
    u_char *out_auth, *out_header, *out_reqid;
    u_char *startData = sn_data;
    int startLength = length;
    long version;
    u_char *origsn_data = sn_data;
    int origlen = length;
    usecEntry *ue;
    int ret = 0, packet_len;

    sidlen = SID_MAX_LEN;
    sn_data = snmp_auth_parse(sn_data, &length, sid, &sidlen, &version);
    if (sn_data == NULL) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse: bad auth encoding\n");
	return 0;
    }
    if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse: wrong version\n");
#ifdef linux
	snmp_inbadversions++;
#endif
	return 0;
    }
    if (version == SNMP_VERSION_2C || version == SNMP_VERSION_2) {
	if (version == SNMP_VERSION_2) {
	    ret = check_auth(session, origsn_data, origlen, sn_data - sidlen, sidlen, &ue);
	    *out_length = (SNMP_MAX_LEN < session->MMS) ? SNMP_MAX_LEN : session->MMS;
	    session->MMS = SNMP_MAX_LEN;

	} else if (version == SNMP_VERSION_2C) {
	    ret = get_community(sid);
	    session->version = SNMP_VERSION_2C;
	}
	if (ret < 0) {
	    increment_stat(-ret);
	    if ((sn_data = asn_parse_header(sn_data, &length, &msgtype)) != NULL
		&& asn_parse_int(sn_data, &length, &type, &reqid, sizeof(reqid))) {
		if (msgtype == REPORT_MSG)
		    return 0;
		if (!(session->qoS & USEC_QOS_GENREPORT))
		    return 0;
		session->agentBoots = _agentBoots;
		session->agentClock = _agentStartTime;
		xmemcpy(session->agentID, _agentID, 12);
		session->MMS = SNMP_MAX_LEN;
		create_report(session, out_sn_data, out_length, -ret, reqid);
		return 1;
	    } else {
		debug(49, 5) ("snmp_agent_parse: asn_parse failed\n");
		return 0;
	    }
	} else if (ret > 0) {
	    increment_stat(ret);
	    debug(49, 5) ("snmp_agent_parse: authorization failed ret=%d\n", ret);
	    return 0;
	}
    } else if (version == SNMP_VERSION_1) {
	if ((ret = get_community(sid)) != 0) {
	    increment_stat(ret);
	    debug(49, 5) ("snmp_agent_parse: get_community failed\n");
	    return 0;
	}
	session->version = SNMP_VERSION_1;
    } else {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse : wrong version\n");
#ifdef linux
	snmp_inbadversions++;
#endif
	return 0;
    }

    sn_data = asn_parse_header(sn_data, &length, &msgtype);
    if (sn_data == NULL) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse: bad header\n");
	return 0;
    }
#ifdef linux
    /* XXX: increment by total number of vars at correct place: */
    snmp_intotalreqvars++;
    if (msgtype == GET_REQ_MSG)
	snmp_ingetrequests++;
    if (msgtype == GETNEXT_REQ_MSG)
	snmp_ingetnexts++;
    if (msgtype == SET_REQ_MSG)
	snmp_insetrequests++;
#endif

    if (msgtype == GETBULK_REQ_MSG) {
	if (session->version == SNMP_VERSION_1) {
	    debug(49, 5) ("snmp_agent_parse: getbulk but version 1\n");
	    return 0;
	}
    } else if (msgtype != GET_REQ_MSG && msgtype != GETNEXT_REQ_MSG && msgtype != SET_REQ_MSG) {
	debug(49, 5) ("snmp_agent_parse: unknown request type\n");
	return 0;
    }
    sn_data = asn_parse_int(sn_data, &length, &type, &reqid, sizeof(reqid));
    if (sn_data == NULL) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse: bad parse of reqid\n");
	return 0;
    }
    sn_data = asn_parse_int(sn_data, &length, &type, &errstat, sizeof(errstat));
    if (sn_data == NULL) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("snmp_agent_parse: bad parse of errstat\n");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return 0;
    }
    sn_data = asn_parse_int(sn_data, &length, &type, &errindex, sizeof(errindex));
    if (sn_data == NULL) {
	increment_stat(SNMP_STAT_ENCODING_ERRORS);
	debug(49, 5) ("bad parse of errindex\n");
	return 0;
    }
    /*
     * Now start cobbling together what is known about the output packet.
     * The final lengths are not known now, so they will have to be recomputed
     * later.
     */

    /* setup for response */
    time((time_t *) & session->agentTime);
    session->agentClock = _agentStartTime;
    session->agentBoots = _agentBoots;
    xmemcpy(session->agentID, _agentID, 12);

    out_auth = out_sn_data;
    out_header = snmp_auth_build(out_auth, out_length, session, 1, 0);
    if (out_header == NULL) {
	debug(49, 5) ("snmp_agent_parse: snmp_auth_build failed\n");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return 0;
    }
    out_reqid = asn_build_sequence(out_header, out_length, (u_char) GET_RSP_MSG, 0);
    if (out_reqid == NULL) {
	debug(49, 5) ("snmp_agent_parse; out_reqid == NULL\n");
	return 0;
    }
    type = (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    /* return identical request id */
    out_sn_data = asn_build_int(out_reqid, out_length, type, &reqid, sizeof(reqid));
    if (out_sn_data == NULL) {
	debug(49, 5) ("snmp_agent_parse; build reqid failed\n");
	return 0;
    }
    /* assume that error status will be zero */
    out_sn_data = asn_build_int(out_sn_data, out_length, type, &zero, sizeof(zero));
    if (out_sn_data == NULL) {
	debug(49, 5) ("snmp_agent_parse: build errstat failed\n");
	return 0;
    }
    /* assume that error index will be zero */
    out_sn_data = asn_build_int(out_sn_data, out_length, type, &zero, sizeof(zero));
    if (out_sn_data == NULL) {
	debug(49, 5) ("snmp_agent_parse: build errindex failed\n");
	return 0;
    }
    if (msgtype == GETBULK_REQ_MSG)
	errstat = bulk_var_op_list(sn_data, length, out_sn_data, *out_length,
	    errstat, errindex, &errindex);
    else
	errstat = parse_var_op_list(sn_data, length, out_sn_data, *out_length,
	    &errindex, msgtype, SNM_RESERVE1);

    if (errstat == SNMP_ERR_NOSUCHNAME) {
	/* see if we have forwarding turned on */
	if (Config.Snmp.localPort != 0) {
	    *ireqid = reqid;
	    return 2;
	}
    }
    if (msgtype == SET_REQ_MSG) {
	if (errstat == SNMP_ERR_NOERROR)
	    errstat = parse_var_op_list(sn_data, length, out_sn_data, *out_length,
		&errindex, msgtype, SNM_RESERVE2);
	if (errstat == SNMP_ERR_NOERROR) {
	    /*
	     * SETS require 3-4 passes through the var_op_list.  The first two
	     * passes verify that all types, lengths, and values are valid
	     * and may reserve resources and the third does the set and a
	     * fourth executes any actions.  Then the identical GET RESPONSE
	     * packet is returned.
	     * If either of the first two passes returns an error, another
	     * pass is made so that any reserved resources can be freed.
	     */
	    parse_var_op_list(sn_data, length, out_sn_data, *out_length,
		&dummyindex, msgtype, SNM_COMMIT);
	    parse_var_op_list(sn_data, length, out_sn_data, *out_length,
		&dummyindex, msgtype, SNM_ACTION);
	    if (create_identical(startData, out_auth, startLength, 0L, 0L)) {
		*out_length = packet_end - out_auth;
		return 1;
	    }
	    debug(49, 5) ("snmp_agent_parse: problem in ERR_NOERROR\n");
	    return 0;
	} else {
	    parse_var_op_list(sn_data, length, out_sn_data, *out_length,
		&dummyindex, msgtype, SNM_FREE);
	}
    }
    switch ((short) errstat) {
    case SNMP_ERR_NOERROR:
	/* re-encode the headers with the real lengths */
	*out_length = packet_end - out_header;
	packet_len = *out_length;
	out_sn_data = asn_build_sequence(out_header, out_length, GET_RSP_MSG,
	    packet_end - out_reqid);
	if (out_sn_data != out_reqid) {
	    debug(49, 5) ("snmp_agent_parse: internal error: header\n");
	    return 0;
	}
	*out_length = packet_end - out_auth;
	out_sn_data = snmp_auth_build(out_auth, out_length, session, 1, packet_end - out_header);

	*out_length = packet_end - out_auth;
#if 0
	/* packet_end is correct for old SNMP.  This dichotomy needs
	 * to be fixed. */
	if (session->version == SNMP_VERSION_2)
	    packet_end = out_auth + packet_len;
#endif
	break;
    case SNMP_ERR_TOOBIG:
	snmp_intoobigs++;
#ifdef NOT_DONE
	if (session->version == SNMP_VERSION_2) {
	    create_toobig(out_auth, *out_length, reqid, pi);
	    break;
	}
	/* else FALLTHRU */
#endif
    case SNMP_ERR_NOACCESS:
    case SNMP_ERR_WRONGTYPE:
    case SNMP_ERR_WRONGLENGTH:
    case SNMP_ERR_WRONGENCODING:
    case SNMP_ERR_WRONGVALUE:
    case SNMP_ERR_NOCREATION:
    case SNMP_ERR_INCONSISTENTVALUE:
    case SNMP_ERR_RESOURCEUNAVAILABLE:
    case SNMP_ERR_COMMITFAILED:
    case SNMP_ERR_UNDOFAILED:
    case SNMP_ERR_AUTHORIZATIONERROR:
    case SNMP_ERR_NOTWRITABLE:
    case SNMP_ERR_INCONSISTENTNAME:
    case SNMP_ERR_NOSUCHNAME:
    case SNMP_ERR_BADVALUE:
    case SNMP_ERR_READONLY:
    case SNMP_ERR_GENERR:
	if (create_identical(startData, out_auth, startLength, errstat,
		errindex)) {
	    *out_length = packet_end - out_auth;
	    return 1;
	}
	debug(49, 5) ("snmp_agent_parse: create_identical failed\n");
	return 0;
    default:
	debug(49, 5) ("snmp_agent_parse: hey, something's wrong\n");
	return 0;
    }

    if (session->qoS & USEC_QOS_AUTH) {
	md5Digest(out_auth, *out_length, out_sn_data - (session->contextLen + 16),
	    out_sn_data - (session->contextLen + 16));
    }
    return 1;
}

/*
 * Parse_var_op_list goes through the list of variables and retrieves each one,
 * placing it's value in the output packet.  In the case of a set request,
 * if action is RESERVE, the value is just checked for correct type and
 * value, and resources may need to be reserved.  If the action is COMMIT,
 * the variable is set.  If the action is FREE, an error was discovered
 * somewhere in the previous RESERVE pass, so any reserved resources
 * should be FREE'd.
 * If any error occurs, an error code is returned.
 */
int
parse_var_op_list(u_char *sn_data,
     int length,
     u_char *out_sn_data,
     int out_length,
     long *index,
     int msgtype,
     int action)
{
    u_char type;
    oid var_name[MAX_NAME_LEN];
    int var_name_len, var_val_len;
    u_char var_val_type, *var_val, statType;
    u_char *statP;
    int statLen = 0;
    u_short acl;
    int rw, exact, err;
    int (*write_method) ();
    u_char *headerP, *var_list_start;
    int dummyLen;
    u_char *getStatPtr();
    int noSuchObject;

    if (msgtype == SET_REQ_MSG)
	rw = WRITE;
    else
	rw = READ;
    if (msgtype == GETNEXT_REQ_MSG) {
	exact = FALSE;
    } else {
	exact = TRUE;
    }
    sn_data = asn_parse_header(sn_data, &length, &type);
    if (sn_data == NULL) {
	debug(49, 5) ("parse_var_op_list: not enough space for varlist\n");
	return PARSE_ERROR;
    }
    if (type != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
	debug(49, 5) ("parse_var_op_list: wrong type\n");
	return PARSE_ERROR;
    }
    headerP = out_sn_data;
    out_sn_data = asn_build_sequence(out_sn_data, &out_length,
	(u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_sn_data == (u_char *) NULL) {
	debug(49, 5) ("parse_var_op_list: not enough space in output packet\n");
	return BUILD_ERROR;
    }
    var_list_start = out_sn_data;

    *index = 1;
    while ((int) length > 0) {
	/* parse the name, value pair */
	var_name_len = MAX_NAME_LEN;
	sn_data = snmp_parse_var_op(sn_data, var_name, &var_name_len, &var_val_type,
	    &var_val_len, &var_val, (int *) &length);
	if (sn_data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	debug(49, 5) ("snmp:before getStatPtr...\n");
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
	    exact, &write_method, session->version, &noSuchObject,
	    msgtype == SET_REQ_MSG ? session->writeView : session->readView);
	if (session->version == SNMP_VERSION_1 && statP == NULL
	    && (msgtype != SET_REQ_MSG || !write_method)) {
	    debug(49, 5) ("parse_var_op_list: internal v1_error\n");
	    return SNMP_ERR_NOSUCHNAME;
	}
	/* check if this variable is read-write (in the MIB sense). */
	if (msgtype == SET_REQ_MSG && acl != RWRITE)
	    return session->version == SNMP_VERSION_1 ? SNMP_ERR_NOSUCHNAME : SNMP_ERR_NOTWRITABLE;

	/* Its bogus to check here on getnexts - the whole packet shouldn't
	 * be dumped - this should should be the loop in getStatPtr
	 * luckily no objects are set unreadable.  This can still be
	 * useful for sets to determine which are intrinsically writable */

	if (msgtype == SET_REQ_MSG) {
	    if (write_method == NULL) {
		if (statP != NULL) {
		    /* see if the type and value is consistent with this
		     * entity's variable */
		    if (!goodValue(var_val_type, var_val_len, statType,
			    statLen)) {
			if (session->version != SNMP_VERSION_1)
			    return SNMP_ERR_WRONGTYPE;	/* poor approximation */
			else {
			    snmp_inbadvalues++;
			    return SNMP_ERR_BADVALUE;
			}
		    }
		    /* actually do the set if necessary */
		    if (action == SNM_COMMIT)
			setVariable(var_val, var_val_type, var_val_len,
			    statP, statLen);
		} else {
		    if (session->version != SNMP_VERSION_1)
			return SNMP_ERR_NOCREATION;
		    else
			return SNMP_ERR_NOSUCHNAME;
		}
	    } else {
		err = (*write_method) (action, var_val, var_val_type,
		    var_val_len, statP, var_name,
		    var_name_len);

		/*
		 * Map the SNMPv2 error codes to SNMPv1 error codes (RFC 2089).
		 */

		if (session->version == SNMP_VERSION_1) {
		    switch (err) {
		    case SNMP_ERR_NOERROR:
			/* keep the no-error error: */
			break;
		    case SNMP_ERR_WRONGVALUE:
		    case SNMP_ERR_WRONGENCODING:
		    case SNMP_ERR_WRONGTYPE:
		    case SNMP_ERR_WRONGLENGTH:
		    case SNMP_ERR_INCONSISTENTVALUE:
			err = SNMP_ERR_BADVALUE;
			break;
		    case SNMP_ERR_NOACCESS:
		    case SNMP_ERR_NOTWRITABLE:
		    case SNMP_ERR_NOCREATION:
		    case SNMP_ERR_INCONSISTENTNAME:
		    case SNMP_ERR_AUTHORIZATIONERROR:
			err = SNMP_ERR_NOSUCHNAME;
			break;
		    default:
			err = SNMP_ERR_GENERR;
			break;
		    }
		}
		if (err != SNMP_ERR_NOERROR) {
		    if (session->version == SNMP_VERSION_1) {
			snmp_inbadvalues++;
		    }
		    return err;
		}
	    }
	} else {
	    /* retrieve the value of the variable and place it into the
	     * outgoing packet */
	    if (statP == NULL) {
		statLen = 0;
		if (exact) {
		    if (noSuchObject == TRUE) {
			statType = SNMP_NOSUCHOBJECT;
		    } else {
			statType = SNMP_NOSUCHINSTANCE;
		    }
		} else {
		    statType = SNMP_ENDOFMIBVIEW;
		}
	    }
	    out_sn_data = snmp_build_var_op(out_sn_data, var_name, &var_name_len,
		statType, statLen, statP,
		&out_length);
	    if (out_sn_data == NULL) {
		return SNMP_ERR_TOOBIG;
	    }
	}

	(*index)++;
    }
    if (msgtype != SET_REQ_MSG) {
	/* save a pointer to the end of the packet */
	packet_end = out_sn_data;

	/* Now rebuild header with the actual lengths */
	dummyLen = packet_end - var_list_start;
	if (asn_build_sequence(headerP, &dummyLen,
		(u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
		dummyLen) == NULL) {
	    return SNMP_ERR_TOOBIG;	/* bogus error ???? */
	}
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}

/*
 * create a packet identical to the input packet, except for the error status
 * and the error index which are set according to the input variables.
 * Returns 1 upon success and 0 upon failure.
 */
int
create_identical(u_char *snmp_in,
     u_char *snmp_out,
     int snmp_length,
     long errstat,
     long errindex)
{
    u_char *sn_data;
    u_char type;
    u_long dummy;
    int length, headerLength;
    u_char *headerPtr, *reqidPtr, *errstatPtr, *errindexPtr, *varListPtr;

    memcpy((char *) snmp_out, (char *) snmp_in, snmp_length);
    length = snmp_length;
    headerPtr = snmp_auth_parse(snmp_out, &length, sid, &sidlen, (long *) &dummy);
    sid[sidlen] = 0;
    if (headerPtr == NULL)
	return 0;
    reqidPtr = asn_parse_header(headerPtr, &length, (u_char *) & dummy);
    if (reqidPtr == NULL)
	return 0;
    headerLength = length;
    errstatPtr = asn_parse_int(reqidPtr, &length, &type, (long *) &dummy, sizeof dummy);	/* request id */
    if (errstatPtr == NULL)
	return 0;
    errindexPtr = asn_parse_int(errstatPtr, &length, &type, (long *) &dummy, sizeof dummy);	/* error status */
    if (errindexPtr == NULL)
	return 0;
    varListPtr = asn_parse_int(errindexPtr, &length, &type, (long *) &dummy, sizeof dummy);	/* error index */
    if (varListPtr == NULL)
	return 0;

    sn_data = asn_build_header(headerPtr, &headerLength, GET_RSP_MSG, headerLength);
    if (sn_data != reqidPtr)
	return 0;
    length = snmp_length;
    type = (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    sn_data = asn_build_int(errstatPtr, &length, type, &errstat, sizeof errstat);
    if (sn_data != errindexPtr)
	return 0;
    sn_data = asn_build_int(errindexPtr, &length, type, &errindex, sizeof errindex);
    if (sn_data != varListPtr)
	return 0;
    packet_end = snmp_out + snmp_length;
    return 1;
}

static int
check_auth(struct snmp_session *session,
     u_char *sn_data,
     int length,
     u_char *pp,
     int plen,
     usecEntry **ueret)
{
    usecEntry *ue;
    Parameters params;
    int ret;

    memset(session, 0, sizeof(*session));

    *ueret = NULL;

    session->version = SNMP_VERSION_2;

    if ((ret = parse_parameters(pp, plen, &params)))
	return ret;

    /* setup session record for this packet */
    /* setup before any error detection so report may be generated if required */
    session->qoS = params.qoS;
    xmemcpy(session->userName, params.userName, params.userLen);
    session->userLen = params.userLen;
    session->MMS = params.MMS;
    session->contextLen = params.contextLen;
    xmemcpy(session->contextSelector, params.contextSelector, params.contextLen);

    /* agentID must be my agentID */
    if (memcmp(_agentID, params.agentID, 12) != 0)
	return -USEC_STAT_UNKNOWN_CONTEXT_SELECTORS;

    /* only support the contextSelector of "" */
    if (params.contextLen != 0)
	return -USEC_STAT_UNKNOWN_CONTEXT_SELECTORS;

    /* lookup the user in my local configuration sn_datastore (LCD) */
    for (ue = users; ue; ue = ue->next) {
	if (ue->userLen != params.userLen)
	    continue;
	if (memcmp(ue->userName, params.userName, params.userLen) == 0)
	    break;
    }

    /* if reached end of sn_datastore, user not found */
    if (ue == NULL)
	return -USEC_STAT_UNKNOWN_USERNAMES;


    /* verify that the requested qoS is supported by the userName */
    if ((u_char) (params.qoS & USEC_QOS_AUTHPRIV) > ue->qoS)
	return -USEC_STAT_UNSUPPORTED_QOS;

    xmemcpy(session->authKey, ue->authKey, 16);

    /* check digest and timeliness if this is an auth message */
    if (params.qoS & USEC_QOS_AUTH) {
	int upper, lower, agentTime;

	/* check the digest */
	xmemcpy(params.authDigestPtr, ue->authKey, 16);
	md5Digest(sn_data, length, ue->authKey, params.authDigestPtr);
	if (memcmp(params.authDigest, params.authDigestPtr, 16) != 0)
	    return -USEC_STAT_WRONG_DIGEST_VALUES;

	/* check timeliness */
	if (_agentBoots == 0xffffffff || _agentBoots != params.agentBoots)
	    return -USEC_STAT_NOT_IN_WINDOWS;

	agentTime = _agentStartTime + time(NULL);
	upper = agentTime + SNMP_MESSAGE_LIFETIME;
	lower = agentTime - SNMP_MESSAGE_LIFETIME;
	if (lower < 0)
	    lower = 0;
	if (params.agentTime < lower || params.agentTime > upper)
	    return -USEC_STAT_NOT_IN_WINDOWS;

	session->readView = ue->authReadView;
	session->writeView = ue->authWriteView;
    } else {
	session->readView = ue->noauthReadView;
	session->writeView = ue->noauthWriteView;
    }

    return 0;
}

int
get_community(char *sessionid)
{
    communityEntry *cp;
    debug(49, 5) ("get_community: %s\n", sessionid);
    for (cp = Config.Snmp.communities; cp; cp = cp->next) {
	debug(49, 5) ("get_community: %s\n", cp->name);
	if (!strcmp(cp->name, sessionid))
	    break;
    }

    if (cp == NULL) {
	snmp_inbadcommunitynames++;
	return SNMP_STAT_V1_BAD_COMMUNITY_NAMES;
    }
    memset(session, 0, sizeof(*session));
    session->community = sessionid;
    session->community_len = strlen(sessionid);
    session->readView = cp->readView;
    session->writeView = cp->writeView;

    return 0;
}

static int
goodValue(u_char inType, int inLen, u_char actualType, int actualLen)
{
    if (inLen > actualLen)
	return FALSE;
    return (inType == actualType);
}


static void
setVariable(u_char *var_val,
     u_char var_val_type,
     int var_val_len,
     u_char *statP,
     int statLen)
{
    int buffersize = 1000;

    switch (var_val_type) {
    case ASN_INTEGER:
    case COUNTER:
    case GAUGE:
    case TIMETICKS:
	asn_parse_int(var_val, &buffersize, &var_val_type, (long *) statP, statLen);
	break;
    case ASN_OCTET_STR:
    case IPADDRESS:
    case OPAQUE:
	asn_parse_string(var_val, &buffersize, &var_val_type, statP, &statLen);
	break;
    case ASN_OBJECT_ID:
	asn_parse_objid(var_val, &buffersize, &var_val_type, (oid *) statP, &statLen);
	break;
    }
}

struct repeater {
    oid name[MAX_NAME_LEN];
    int length;
} repeaterList[20];


static int
bulk_var_op_list(u_char *sn_data,
     int length,
     u_char *out_sn_data,
     int out_length,
     int non_repeaters,
     int max_repetitions,
     long *index)
{
    u_char type;
    oid var_name[MAX_NAME_LEN];
    int var_name_len, var_val_len;
    u_char var_val_type, *var_val, statType;
    u_char *statP;
    int statLen;
    u_short acl;
    int (*write_method) ();
    u_char *headerP, *var_list_start;
    int dummyLen;
    u_char *getStatPtr();
    u_char *repeaterStart, *out_sn_data_save;
    int repeatCount, repeaterLength, indexStart, out_length_save;
    int full = FALSE;
    int noSuchObject, useful;
    int repeaterIndex, repeaterCount;
    struct repeater *rl;

    if (non_repeaters < 0)
	non_repeaters = 0;
    max_repetitions = *index;
    if (max_repetitions < 0)
	max_repetitions = 0;

    sn_data = asn_parse_header(sn_data, &length, &type);
    if (sn_data == NULL) {
	debug(49, 5) ("bulk_var_op_list: not enough space for varlist\n");
	snmp_inasnparseerrors++;
	return PARSE_ERROR;
    }
    if (type != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
	debug(49, 5) ("bulk_var_op_list: wrong type\n");
	snmp_inasnparseerrors++;
	return PARSE_ERROR;
    }
    headerP = out_sn_data;
    out_sn_data = asn_build_sequence(out_sn_data, &out_length,
	(u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_sn_data == NULL) {
	debug(49, 5) ("bulk_var_op_list: not enough space in output packet\n");
	return BUILD_ERROR;
    }
    var_list_start = out_sn_data;

    out_length -= 32;		/* slop factor */
    *index = 1;
    while ((int) length > 0 && non_repeaters > 0) {
	/* parse the name, value pair */

	var_name_len = MAX_NAME_LEN;
	sn_data = snmp_parse_var_op(sn_data, var_name, &var_name_len, &var_val_type,
	    &var_val_len, &var_val, (int *) &length);
	if (sn_data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
	    FALSE, &write_method, session->version, &noSuchObject, session->readView);

	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;

	/* save out_sn_data so this varbind can be removed if it goes over
	 * the limit for this packet */

	/* retrieve the value of the variable and place it into the outgoing packet */
	out_sn_data = snmp_build_var_op(out_sn_data, var_name, &var_name_len,
	    statType, statLen, statP,
	    &out_length);
	if (out_sn_data == NULL) {
	    return SNMP_ERR_TOOBIG;	/* ??? */
	}
	(*index)++;
	non_repeaters--;
    }

    repeaterStart = out_sn_data;
    indexStart = *index;	/* index on input packet */

    repeaterCount = 0;
    rl = repeaterList;
    useful = FALSE;
    while ((int) length > 0) {
	/* parse the name, value pair */
	rl->length = MAX_NAME_LEN;
	sn_data = snmp_parse_var_op(sn_data, rl->name, &rl->length,
	    &var_val_type, &var_val_len, &var_val,
	    (int *) &length);
	if (sn_data == NULL) {
	    snmp_inasnparseerrors++;
	    return PARSE_ERROR;
	}
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(rl->name, &rl->length, &statType, &statLen,
	    &acl, FALSE, &write_method, session->version, &noSuchObject, session->readView);
	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;
	else
	    useful = TRUE;

	out_sn_data_save = out_sn_data;
	out_length_save = out_length;
	/* retrieve the value of the variable and place it into the
	 * outgoing packet */
	out_sn_data = snmp_build_var_op(out_sn_data, rl->name, &rl->length,
	    statType, statLen, statP,
	    &out_length);
	if (out_sn_data == NULL) {
	    out_sn_data = out_sn_data_save;
	    out_length = out_length_save;
	    full = TRUE;
	}
	(*index)++;
	repeaterCount++;
	rl++;
    }
    repeaterLength = out_sn_data - repeaterStart;
    if (!useful)
	full = TRUE;

    for (repeatCount = 1; repeatCount < max_repetitions; repeatCount++) {
	sn_data = repeaterStart;
	length = repeaterLength;
	*index = indexStart;
	repeaterStart = out_sn_data;
	useful = FALSE;
	repeaterIndex = 0;
	rl = repeaterList;
	while ((repeaterIndex++ < repeaterCount) > 0 && !full) {
	    /* now attempt to retrieve the variable on the local entity */
	    statP = getStatPtr(rl->name, &rl->length, &statType, &statLen,
		&acl, FALSE, &write_method, session->version, &noSuchObject, session->readView);
	    if (statP == NULL)
		statType = SNMP_ENDOFMIBVIEW;
	    else
		useful = TRUE;

	    out_sn_data_save = out_sn_data;
	    out_length_save = out_length;
	    /* retrieve the value of the variable and place it into the
	     * Outgoing packet */
	    out_sn_data = snmp_build_var_op(out_sn_data, rl->name, &rl->length, statType, statLen, statP, &out_length);
	    if (out_sn_data == NULL) {
		out_sn_data = out_sn_data_save;
		out_length = out_length_save;
		full = TRUE;
		repeatCount = max_repetitions;
	    }
	    (*index)++;
	    rl++;
	}
	repeaterLength = out_sn_data - repeaterStart;
	if (!useful)
	    full = TRUE;
    }
    packet_end = out_sn_data;

    /* Now rebuild header with the actual lengths */
    dummyLen = out_sn_data - var_list_start;
    if (asn_build_sequence(headerP, &dummyLen, (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen) == NULL) {
	return SNMP_ERR_TOOBIG;	/* bogus error ???? */
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}
