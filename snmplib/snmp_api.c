

/**********************************************************************
 *
 *           Copyright 1997 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 **********************************************************************/

#include "config.h"

#include <stdio.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include "asn1.h"
#include "snmp.h"

#include "snmp-internal.h"
#include "snmp_impl.h"
#include "snmp_session.h"
#if 0
#include "mibii.h"
#include "snmp_dump.h"
#endif
#include "snmp_error.h"
#include "snmp_vars.h"
#include "snmp_pdu.h"
#include "snmp_msg.h"

#include "snmp_api.h"
#if 0
#include "snmp_client.h"
#endif
#include "snmp_api_error.h"
#include "snmp_api_util.h"

#include "util.h"

extern int snmp_errno;


/*#define DEBUG_API 1 */

/*
 * RFC 1906: Transport Mappings for SNMPv2
 */


oid default_enterprise[] =
{1, 3, 6, 1, 4, 1, 3, 1, 1};	/* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_RETRIES	    4
#define DEFAULT_TIMEOUT	    1000000L
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0

extern int snmp_errno;


struct session_list *Sessions = NULL;

#if 0
/*
 * Get initial request ID for all transactions.
 */
static int Reqid = 0;

static void 
init_snmp(void)
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) 0);
    squid_srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = squid_random();
}


/*
 * Free each element in the input request list.
 */
static void 
free_request_list(rp)
     struct request_list *rp;
{
    struct request_list *orp;

    while (rp) {
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	xfree((char *) orp);
    }
}

#endif

/**********************************************************************/

/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
#if 0
struct snmp_session *
snmp_open(struct snmp_session *session)
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_int addr;
    struct sockaddr_in me;
    struct hostent *hp;
    struct servent *servp;

    if (Reqid == 0)
	init_snmp();

    /* Copy session structure and link into list */
    slp = (struct session_list *) xmalloc(sizeof(struct session_list));
    if (slp == NULL) {
	snmp_set_api_error(SNMPERR_OS_ERR);
	return (NULL);
    }
    /* Internal session */
    isp = (struct snmp_internal_session *) xmalloc(sizeof(struct snmp_internal_session));
    if (isp == NULL) {
	xfree(slp);
	snmp_set_api_error(SNMPERR_OS_ERR);
	return (NULL);
    }
    slp->internal = isp;
    memset((char *) isp, '\0', sizeof(struct snmp_internal_session));
    slp->internal->sd = -1;	/* mark it not set */

    /* The actual session */
    slp->session = (struct snmp_session *) xmalloc(sizeof(struct snmp_session));
    if (slp->session == NULL) {
	xfree(isp);
	xfree(slp);
	snmp_set_api_error(SNMPERR_OS_ERR);
	return (NULL);
    }
    xmemcpy((char *) slp->session, (char *) session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL) {
	cp = (u_char *) xmalloc((unsigned) strlen(session->peername) + 1);
	if (cp == NULL) {
	    xfree(slp->session);
	    xfree(isp);
	    xfree(slp);
	    snmp_set_api_error(SNMPERR_OS_ERR);
	    return (NULL);
	}
	strcpy((char *) cp, session->peername);
	session->peername = (char *) cp;
    }
    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN) {
	cp = (u_char *) xmalloc((unsigned) session->community_len);
	if (cp)
	    xmemcpy((char *) cp, (char *) session->community, session->community_len);
    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *) xmalloc((unsigned) session->community_len);
	if (cp)
	    xmemcpy((char *) cp, (char *) DEFAULT_COMMUNITY,
		session->community_len);
    }
    if (cp == NULL) {
	xfree(session->peername);
	xfree(slp->session);
	xfree(isp);
	xfree(slp);
	snmp_set_api_error(SNMPERR_OS_ERR);
	return (NULL);
    }
    session->community = cp;	/* replace pointer with pointer to new data */

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = DEFAULT_TIMEOUT;
    isp->requests = NULL;

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
	perror("socket");
	snmp_set_api_error(SNMPERR_OS_ERR);
	if (!snmp_close(session)) {
	    snmplib_debug(5, "Couldn't abort session: %s. Exiting\n",
		api_errstring(snmp_errno));
	    exit(1);
	}
	return (NULL);
    }
#ifdef SO_BSDCOMPAT
    /* Patch for Linux.  Without this, UDP packets that fail get an ICMP
     * response.  Linux turns the failed ICMP response into an error message
     * and return value, unlike all other OS's.
     */
    {
	int one = 1;
	setsockopt(sd, SOL_SOCKET, SO_BSDCOMPAT, &one, sizeof(one));
    }
#endif /* SO_BSDCOMPAT */

    isp->sd = sd;
    if (session->peername != SNMP_DEFAULT_PEERNAME) {
	if ((addr = inet_addr(session->peername)) != -1) {
	    xmemcpy((char *) &isp->addr.sin_addr, (char *) &addr,
		sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL) {
		snmplib_debug(3, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)) {
		    snmplib_debug(3, "Couldn't abort session: %s. Exiting\n",
			api_errstring(snmp_errno));
		    exit(2);
		}
		return (NULL);
	    } else {
		xmemcpy((char *) &isp->addr.sin_addr, (char *) hp->h_addr,
		    hp->h_length);
	    }
	}

	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT) {
	    servp = getservbyname("snmp", "udp");
	    if (servp != NULL) {
		isp->addr.sin_port = servp->s_port;
	    } else {
		isp->addr.sin_port = htons(SNMP_PORT);
	    }
	} else {
	    isp->addr.sin_port = htons(session->remote_port);
	}
    } else {
	isp->addr.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    }

    memset(&me, '\0', sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *) &me, sizeof(me)) != 0) {
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (!snmp_close(session)) {
	    snmplib_debug(3, "Couldn't abort session: %s. Exiting\n",
		api_errstring(snmp_errno));
	    exit(3);
	}
	return (NULL);
    }
    return (session);
}


/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(struct snmp_session *session)
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session) {		/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for (slp = Sessions; slp; slp = slp->next) {
	    if (slp->session == session) {
		if (oslp)	/* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }

    /* If we found the session, free all data associated with it */
    if (slp) {
	if (slp->session->community != NULL)
	    xfree((char *) slp->session->community);
	if (slp->session->peername != NULL)
	    xfree((char *) slp->session->peername);
	xfree((char *) slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	xfree((char *) slp->internal);
	xfree((char *) slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return (0);
    }
    return (1);
}
#endif

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the encoded packet in out_length.  If an error
 * occurs, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
     u_char *packet;
     int *out_length;
{
    u_char *bufp;

    bufp = snmp_msg_Encode(packet, out_length,
	session->community, session->community_len,
	session->Version,
	pdu);
    snmplib_debug(8, "LIBSNMP: snmp_build():  Packet len %d (requid %d)\n",
	*out_length, pdu->reqid);

    if (bufp == NULL)
	return (-1);

    return (0);
}

/*
 * Parses the packet recieved on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, NULL is returned.  If not, the community is.
 */
u_char *
snmp_parse(struct snmp_session * session,
    struct snmp_pdu * pdu,
    u_char * data,
    int length)
{
    u_char Community[128];
    u_char *bufp;
    int CommunityLen = 128;

    /* Decode the entire message. */
    data = snmp_msg_Decode(data, &length,
	Community, &CommunityLen,
	&session->Version, pdu);
    if (data == NULL)
	return (NULL);

    bufp = (u_char *) xmalloc(CommunityLen + 1);
    if (bufp == NULL)
	return (NULL);

    strcpy((char *) bufp, (char *) Community);
    return (bufp);
}

/*
 * Sends the input pdu on the session after calling snmp_build to create
 * a serialized packet.  If necessary, set some of the pdu data from the
 * session defaults.  Add a request corresponding to this pdu to the list
 * of outstanding requests on this session, then send the pdu.
 * Returns the request id of the generated packet if applicable, otherwise 1.
 * On any error, 0 is returned.
 * The pdu is freed by snmp_send() unless a failure occured.
 */
#if 0
int 
snmp_send(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    if (Reqid == 0)
	init_snmp();

    for (slp = Sessions; slp; slp = slp->next) {
	if (slp->session == session) {
	    isp = slp->internal;
	    break;
	}
    }
    if (isp == NULL) {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == SNMP_PDU_GET ||
	pdu->command == SNMP_PDU_GETNEXT ||
	pdu->command == SNMP_PDU_RESPONSE ||
	pdu->command == SNMP_PDU_SET) {

	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;

    } else if (pdu->command == SNMP_PDU_INFORM ||
	    pdu->command == SNMP_PDU_GETBULK ||
	pdu->command == SNMP_PDU_V2TRAP) {

	if (session->Version != SNMP_VERSION_2) {
	    snmplib_debug(3, "Cant send SNMPv2 PDU's in SNMP message.\n");
	    snmp_errno = SNMPERR_GENERR;	/* Fix this XXXXX */
	    return 0;
	}
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;

    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;		/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH) {
	    pdu->enterprise = (oid *) xmalloc(sizeof(DEFAULT_ENTERPRISE));
	    xmemcpy((char *) pdu->enterprise, (char *) DEFAULT_ENTERPRISE,
		sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE) / sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }

    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS) {
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS) {
	    xmemcpy((char *) &pdu->address, (char *) &isp->addr,
		sizeof(pdu->address));
	} else {
	    snmplib_debug(3, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
    if (snmp_build(session, pdu, packet, &length) < 0) {
	snmplib_debug(3, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    snmp_dump(packet, length, "sending", pdu->address.sin_addr);

    gettimeofday(&tv, (struct timezone *) 0);
    if (sendto(isp->sd, (char *) packet, length, 0,
	    (struct sockaddr *) &pdu->address, sizeof(pdu->address)) < 0) {
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    snmplib_debug(6, "LIBSNMP:  Sent PDU %s, Reqid %d\n",
	snmp_pdu_type(pdu), pdu->reqid);

    if (pdu->command == SNMP_PDU_GET ||
	pdu->command == SNMP_PDU_GETNEXT ||
	pdu->command == SNMP_PDU_SET ||
	pdu->command == SNMP_PDU_GETBULK ||
	pdu->command == SNMP_PDU_INFORM) {

	snmplib_debug(6, "LIBSNMP:  Setting up to recieve a response for reqid %d\n",
	    pdu->reqid);

	/* set up to expect a response */
	rp = (struct request_list *) xmalloc(sizeof(struct request_list));
	rp->next_request = isp->requests;
	isp->requests = rp;

	rp->pdu = pdu;
	rp->request_id = pdu->reqid;

	rp->retries = 1;
	rp->timeout = session->timeout;
	rp->time = tv;
	tv.tv_usec += rp->timeout;
	tv.tv_sec += tv.tv_usec / 1000000L;
	tv.tv_usec %= 1000000L;
	rp->expire = tv;
    }
    return (pdu->reqid);
}

/*
 * Checks to see if any of the fd's set in the fdset belong to
 * snmp.  Each socket with it's fd set has a packet read from it
 * and snmp_parse is called on the packet received.  The resulting pdu
 * is passed to the callback routine for that session.  If the callback
 * routine returns successfully, the pdu and it's request are deleted.
 */
void
snmp_read(fdset)
     fd_set *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in from;
    int length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp, *orp;
    u_char *bufp;

    for (slp = Sessions; slp; slp = slp->next) {
	if (FD_ISSET(slp->internal->sd, fdset)) {
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof from;
	    length = recvfrom(isp->sd, (char *) packet,
		PACKET_LENGTH, 0, (struct sockaddr *) &from,
		&fromlength);
	    if (length == -1)
		perror("recvfrom");

	    snmp_dump(packet, length, "received", from.sin_addr);

	    pdu = snmp_pdu_create(0);
	    pdu->address = from;
	    pdu->reqid = 0;

	    /* Parse the incoming packet */
	    bufp = snmp_parse(sp, pdu, packet, length);
	    if (bufp == NULL) {
		snmplib_debug(3, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }
	    if (sp->community)
		xfree(sp->community);
	    sp->community = bufp;
	    sp->community_len = strlen((char *) bufp);

	    snmplib_debug(6, "LIBSNMP:  Read PDU %s, ReqId %d\n", snmp_pdu_type(pdu), pdu->reqid);

	    if (pdu->command == SNMP_PDU_RESPONSE) {
		for (rp = isp->requests; rp; rp = rp->next_request) {
		    if (rp->request_id == pdu->reqid) {
			snmplib_debug(6, "LIBSNMP:  ReqId %d:  Calling callback\n", pdu->reqid);
			if (sp->callback(RECEIVED_MESSAGE, sp,
				pdu->reqid, pdu,
				sp->callback_magic) == 1) {
			    /* successful, so delete request */
			    snmplib_debug(6, "LIBSNMP:  ReqId %d:  Success.  Removing ReqId.\n", pdu->reqid);
			    orp = rp;
			    if (isp->requests == orp) {
				/* first in list */
				isp->requests = orp->next_request;
			    } else {
				for (rp = isp->requests; rp; rp = rp->next_request) {
				    if (rp->next_request == orp) {
					/* link around it */
					rp->next_request = orp->next_request;
					break;
				    }
				}
			    }
			    snmp_free_pdu(orp->pdu);
			    xfree((char *) orp);
			    /* there shouldn't be another req with the same reqid */
			    break;
			}
		    }
		}
	    } else if (pdu->command == SNMP_PDU_GET ||
		    pdu->command == SNMP_PDU_GETNEXT ||
		    pdu->command == TRP_REQ_MSG ||
		    pdu->command == SNMP_PDU_SET ||
		    pdu->command == SNMP_PDU_GETBULK ||
		    pdu->command == SNMP_PDU_INFORM ||
		pdu->command == SNMP_PDU_V2TRAP) {
		sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid,
		    pdu, sp->callback_magic);
	    }
	    snmp_free_pdu(pdu);
	}
    }
}

/*
 * Returns info about what snmp requires from a select statement.
 * numfds is the number of fds in the list that are significant.
 * All file descriptors opened for SNMP are OR'd into the fdset.
 * If activity occurs on any of these file descriptors, snmp_read
 * should be called with that file descriptor set
 *
 * The timeout is the latest time that SNMP can wait for a timeout.  The
 * select should be done with the minimum time between timeout and any other
 * timeouts necessary.  This should be checked upon each invocation of select.
 * If a timeout is received, snmp_timeout should be called to check if the
 * timeout was for SNMP.  (snmp_timeout is idempotent)
 *
 * Block is 1 if the select is requested to block indefinitely, rather than time out.
 * If block is input as 1, the timeout value will be treated as undefined, but it must
 * be available for setting in snmp_select_info.  On return, if block is true, the value
 * of timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The number of sessions open)
 */
int
snmp_select_info(numfds, fdset, timeout, block)
     int *numfds;
     fd_set *fdset;
     struct timeval *timeout;
     int *block;		/* should the select block until input arrives (i.e. no input) */
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    struct request_list *rp;
    struct timeval now, earliest;
    int active = 0, requests = 0;

    timerclear(&earliest);
    /*
     * For each request outstanding, add it's socket to the fdset,
     * and if it is the earliest timeout to expire, mark it as lowest.
     */
    for (slp = Sessions; slp; slp = slp->next) {

	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	snmplib_debug(6, "LIBSNMP:  select():  Adding port %d\n", isp->sd);
	if (isp->requests) {
	    /* found another session with outstanding requests */
	    requests++;
	    for (rp = isp->requests; rp; rp = rp->next_request) {
		if (!timerisset(&earliest) ||
		    timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    snmplib_debug(6, "LIBSNMP:  Select Info:  %d active, %d requests pending.\n",
	active, requests);

    if (requests == 0)		/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *) 0);
    earliest.tv_sec--;		/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L) {
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0) {
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }
    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)) {
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/*
 * snmp_timeout should be called whenever the timeout from snmp_select_info 
 * expires, but it is idempotent, so snmp_timeout can be polled (probably a 
 * cpu expensive proposition).  snmp_timeout checks to see if any of the 
 * sessions have an outstanding request that has timed out.  If it finds one 
 * (or more), and that pdu has more retries available, a new packet is formed
 * from the pdu and is resent.  If there are no more retries available, the 
 * callback for the session is used to alert the user of the timeout.
 */
void 
snmp_timeout(void)
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    struct request_list *rp, *orp, *freeme = NULL;
    struct timeval now;

    gettimeofday(&now, (struct timezone *) 0);

    /*
     * For each request outstanding, check to see if it has expired.
     */
    for (slp = Sessions; slp; slp = slp->next) {
	sp = slp->session;
	isp = slp->internal;
	orp = NULL;
	snmplib_debug(6, "LIBSNMP:  Checking session %s\n",
	    (sp->peername != NULL) ? sp->peername : "<NULL>");
	for (rp = isp->requests; rp; rp = rp->next_request) {
	    snmplib_debug(6, "LIBSNMP:  Checking session request %d, expire at %u, Retry %d/%d\n",
		rp->request_id, rp->expire.tv_sec, rp->retries, sp->retries);

	    if (freeme != NULL) {
		/* frees rp's after the for loop goes on to the next_request */
		xfree((char *) freeme);
		freeme = NULL;
	    }
	    if (timercmp(&rp->expire, &now, <)) {

		snmplib_debug(6, "LIBSNMP:  Expired.\n");

		/* this timer has expired */
		if (rp->retries >= sp->retries) {
		    /* No more chances, delete this entry */
		    sp->callback(TIMED_OUT, sp, rp->pdu->reqid,
			rp->pdu, sp->callback_magic);
		    if (orp == NULL) {
			isp->requests = rp->next_request;
		    } else {
			orp->next_request = rp->next_request;
		    }
		    snmp_free_pdu(rp->pdu);
		    freeme = rp;
		    continue;	/* don't update orp below */
		} else {
		    u_char packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    snmplib_debug(6, "LIBSNMP:  Retransmitting.\n");
		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length) < 0) {
			snmplib_debug(3, "Error building packet\n");
		    }
		    snmp_dump(packet, length,
			"sending", rp->pdu->address.sin_addr);

		    gettimeofday(&tv, (struct timezone *) 0);
		    if (sendto(isp->sd, (char *) packet, length, 0, (struct sockaddr *) &rp->pdu->address, sizeof(rp->pdu->address)) < 0) {
			perror("sendto");
		    }
		    rp->time = tv;
		    tv.tv_usec += rp->timeout;
		    tv.tv_sec += tv.tv_usec / 1000000L;
		    tv.tv_usec %= 1000000L;
		    rp->expire = tv;
		}
	    }
	    orp = rp;
	}
	if (freeme != NULL) {
	    xfree((char *) freeme);
	    freeme = NULL;
	}
    }
}


/* Print some API stats */
void 
snmp_api_stats(void *outP)
{
    struct session_list *slp;
    struct request_list *rp;
    struct snmp_internal_session *isp;
    FILE *out = (FILE *) outP;

    int active = 0;
    int requests = 0;
    int count = 0;
    int rcount = 0;

    fprintf(out, "LIBSNMP: Session List Dump\n");
    fprintf(out, "LIBSNMP: ----------------------------------------\n");
    for (slp = Sessions; slp; slp = slp->next) {

	isp = slp->internal;
	active++;
	count++;
	fprintf(out, "LIBSNMP: %2d: Host %s\n", count,
	    (slp->session->peername == NULL) ? "NULL" : slp->session->peername);

	if (isp->requests) {
	    /* found another session with outstanding requests */
	    requests++;
	    rcount = 0;
	    for (rp = isp->requests; rp; rp = rp->next_request) {
		rcount++;
		{
		    struct hostent *hp;
		    hp = gethostbyaddr((char *) &(rp->pdu->address),
			sizeof(u_int), AF_INET);
		    fprintf(out, "LIBSNMP: %2d: ReqId %d (%s) (%s)\n",
			rcount, rp->request_id, snmp_pdu_type(rp->pdu),
			(hp == NULL) ? "NULL" : hp->h_name);
		}
	    }
	}
	fprintf(out, "LIBSNMP: ----------------------------------------\n");
    }
    fprintf(out, "LIBSNMP: Session List: %d active, %d have requests pending.\n",
	active, requests);
}
#endif
