

/***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0	/* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0	/* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] =
{1, 3, 6, 1, 4, 1, 3, 1, 1};	/* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389	/* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int sd;			/* socket descriptor for this connection */
    ipaddr addr;		/* address of connected peer */
    struct request_list *requests;	/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long request_id;		/* request id */
    int retries;		/* Number of retries */
    u_long timeout;		/* length to wait for timeout */
    struct timeval time;	/* Time this request was made */
    struct timeval expire;	/* time this request is due to expire */
    struct snmp_pdu *pdu;	/* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] =
{
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
     int snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR) {
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp()
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) 0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}

#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
     char *packet;
     int length;
     ipaddr addr;
     int code;
{
    if (length < 0) {
	return;
    }
    if (code <= 0) {		/* received */
	printf("\nReceived %4d bytes from ", length);
    } else {			/* sending */
	printf("\nSending  %4d bytes to   ", length);
    }
    printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
    for (count = 0; count < length; count++) {
	if ((count & 15) == 0) {
	    printf("\n  ");
	}
	printf("%02X ", (int) (packet[count] & 255));
    }
#endif
    fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
     struct session_list *slp;
     struct request_list *rp;
     int code;
{
    int reqid = 0, retries = 1;
    if (rp) {
	reqid = rp->request_id;
	retries = rp->retries;
    }
    printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
    switch (code) {
    case TRACE_SEND:
	printf("send pdu (%d)", retries);
	break;
    case TRACE_RECV:
	printf("recv pdu");
	break;
    case TRACE_TIMEOUT:
	printf("time out");
	break;
    }
    fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
     struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *) calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *) calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *) isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1;	/* mark it not set */
    slp->session = (struct snmp_session *) calloc(1, sizeof(struct snmp_session));
    bcopy((char *) session, (char *) slp->session, sizeof(struct snmp_session));
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
	cp = (u_char *) calloc(1, (unsigned) strlen(session->peername) + 1);
	strcpy((char *) cp, session->peername);
	session->peername = (char *) cp;
    }
    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0)
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN) {
	if (*session->community == '+') {
	    session->community_len--;
	    cp = (u_char *) calloc(1, (unsigned) session->community_len);
	    bcopy((char *) session->community + 1, (char *) cp,
		session->community_len);
	    session->version = SNMP_VERSION_2C;
	} else {
	    cp = (u_char *) calloc(1, (unsigned) session->community_len);
	    bcopy((char *) session->community, (char *) cp,
		session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *) calloc(1, (unsigned) session->community_len);
	bcopy((char *) DEFAULT_COMMUNITY, (char *) cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)) {
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME) {
	if ((addr = inet_addr(session->peername)) != -1) {
	    bcopy((char *) &addr, (char *) &isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL) {
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)) {
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *) hp->h_addr, (char *) &isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT) {
	    /*servp = getservbyname("snmp", "udp"); */
	    servp = NULL;
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *) &me, sizeof(me)) != 0) {
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (!snmp_close(session)) {
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n",
		api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }
    if (*cp == '/') {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string(session);
	session->qoS |= USEC_QOS_GENREPORT;
    }
    /* replace comm pointer with pointer to new data: */
    session->community = cp;

    return session;
}

void
sync_with_agent(session)
     struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy(session->userName, "public");

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS) {
	memcpy(session->agentID, response->params.agentID, 12);

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	if (status == STAT_TIMEOUT) {
	    printf("No Response from %s\n", session->peername);
	} else {		/* status == STAT_ERROR */
	    printf("An error occurred, Quitting\n");
	}
	exit(-1);
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1/***/ BUG_SNMPTRACE */cked for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    

/***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0	/* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0	/* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] =
{1, 3, 6, 1, 4, 1, 3, 1, 1};	/* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389	/* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int sd;			/* socket descriptor for this connection */
    ipaddr addr;		/* address of connected peer */
    struct request_list *requests;	/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long request_id;		/* request id */
    int retries;		/* Number of retries */
    u_long timeout;		/* length to wait for timeout */
    struct timeval time;	/* Time this request was made */
    struct timeval expire;	/* time this request is due to expire */
    struct snmp_pdu *pdu;	/* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] =
{
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
     int snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR) {
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp()
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) 0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}

#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
     char *packet;
     int length;
     ipaddr addr;
     int code;
{
    if (length < 0) {
	return;
    }
    if (code <= 0) {		/* received */
	printf("\nReceived %4d bytes from ", length);
    } else {			/* sending */
	printf("\nSending  %4d bytes to   ", length);
    }
    printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
    for (count = 0; count < length; count++) {
	if ((count & 15) == 0) {
	    printf("\n  ");
	}
	printf("%02X ", (int) (packet[count] & 255));
    }
#endif
    fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
     struct session_list *slp;
     struct request_list *rp;
     int code;
{
    int reqid = 0, retries = 1;
    if (rp) {
	reqid = rp->request_id;
	retries = rp->retries;
    }
    printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
    switch (code) {
    case TRACE_SEND:
	printf("send pdu (%d)", retries);
	break;
    case TRACE_RECV:
	printf("recv pdu");
	break;
    case TRACE_TIMEOUT:
	printf("time out");
	break;
    }
    fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
     struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *) calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *) calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *) isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1;	/* mark it not set */
    slp->session = (struct snmp_session *) calloc(1, sizeof(struct snmp_session));
    bcopy((char *) session, (char *) slp->session, sizeof(struct snmp_session));
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
	cp = (u_char *) calloc(1, (unsigned) strlen(session->peername) + 1);
	strcpy((char *) cp, session->peername);
	session->peername = (char *) cp;
    }
    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0)
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN) {
	if (*session->community == '+') {
	    session->community_len--;
	    cp = (u_char *) calloc(1, (unsigned) session->community_len);
	    bcopy((char *) session->community + 1, (char *) cp,
		session->community_len);
	    session->version = SNMP_VERSION_2C;
	} else {
	    cp = (u_char *) calloc(1, (unsigned) session->community_len);
	    bcopy((char *) session->community, (char *) cp,
		session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *) calloc(1, (unsigned) session->community_len);
	bcopy((char *) DEFAULT_COMMUNITY, (char *) cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)) {
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME) {
	if ((addr = inet_addr(session->peername)) != -1) {
	    bcopy((char *) &addr, (char *) &isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL) {
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)) {
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *) hp->h_addr, (char *) &isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT) {
	    /*servp = getservbyname("snmp", "udp"); */
	    servp = NULL;
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *) &me, sizeof(me)) != 0) {
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (!snmp_close(session)) {
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n",
		api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }
    if (*cp == '/') {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string(session);
	session->qoS |= USEC_QOS_GENREPORT;
    }
    /* replace comm pointer with pointer to new data: */
    session->community = cp;

    return session;
}

void
sync_with_agent(session)
     struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy(session->userName, "public");

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS) {
	memcpy(session->agentID, response->params.agentID, 12);

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	if (status == STAT_TIMEOUT) {
	    printf("No Response from %s\n", session->peername);
	} else {		/* status == STAT_ERROR */
	    printf("An error occurred, Quitting\n");
	}
	exit(-1);
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
ring(fp, token)
     FILE *fp;
     char *token;
{
    int ch;

    ch = ' ';
    *token = '\0';		/* make the token empty */

    while (ch != -1) {
	ch = getc(fp);
	if (ch == '\n')
	    Line++;
	else if (ch == '"') {
	    return QUOTESTRING;
	}
    }

    return 0;
}

/*
 * This routine parses a string like  { blah blah blah } and returns OBJID if
 * it is well formed, and NULL if not.
 */
static int
tossObjectIdentifier(fp)
     FILE *fp;
{
    int ch;

    ch = getc(fp);
/*    ch = last; = ' '? */
    /* skip all white space */
    while (isspace(ch) && ch != -1) {
	ch = getc(fp);
	if (ch == '\n')
	    Line++;
    }
    if (ch != '{')
	return 0;

    while (ch != -1) {
	ch = getc(fp);

	if (ch == '\n')
	    Line++;
	else if (ch == '}')
	    return OBJID;
    }

/*    last = ch; */
    return 0;
}
rn 0;
    }
    /*
     * Optional parts of the OBJECT-TYPE macro
     */
    type = get_token(fp, token);
    while (type != EQUALS) {
	switch (type) {
	case DESCRIPTION:
	    type = get_token(fp, token);
	    if (type != QUOTESTRING) {
		print_error("Bad DESCRIPTION", token, type);
		free_node(np);
		return 0;
	    }
#ifdef TEST
	    printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
	    np->description = quoted_string_buffer;
	    quoted_string_buffer = (char *) calloc(1, MAXQUOTESTR);
	    break;

	case REFERENCE:
	    type = get_token(fp, token);
	    if (type != QUOTESTRING) {
		print_error("Bad DESCRIPTION", token, type);
		free_node(np);
		return 0;
	    }
	    break;
	case INDEX:
	case DEFVAL:
	case AUGMENTS:
	case NUM_ENTRIES:
	    if (tossObjectIdentifier(fp) != OBJID) {
		print_error("Bad Object Identifier", token, type);
		free_node(np);
		return 0;
	    }
	    break;

	default:
	    print_error("Bad format of optional clauses", token, type);
	    free_node(np);
	    return 0;

	}
	type = get_token(fp, token);
    }
    if (type != EQUALS) {
	print_error("Bad format", token, type);
	free_node(np);
	return 0;
    }
    length = getoid(fp, oid, 32);
    if (length > 1 && length <= 32) {
	/* just take the last pair in the oid list */
	if (oid[length - 2].label)
	    strncpy(np->parent, oid[length - 2].label, MAXLABEL);
	strcpy(np->label, name);
	if (oid[length - 1].subid != -1)
	    np->subid = oid[length - 1].subid;
	else
	    print_error("Warning: This entry is pretty silly", np->label, type);
    } else {
	print_error("No end to oid", (char *) NULL, type);
	free_node(np);
	np = 0;
    }
    /* free oid array */
    for (count = 0; count < length; count++) {
	if (oid[count].label)
	    free(oid[count].label);
	oid[count].label = 0;
    }
    return np;
}


/*
 * Parses an OBJECT GROUP macro.
 * Returns 0 on error.
 */
static struct node *
parse_objectgroup(fp, name)
     FILE *fp;
     char *name;
{
    int type;
    char token[MAXTOKEN];
    int count, length;
    struct subid oid[32];
    struct node *np;

    np = (struct node *) Malloc(sizeof(struct node));
    np->type = 0;
    np->next = 0;
    np->enums = 0;
    np->description = NULL;	/* default to an empty description */
    type = get_token(fp, token);
    while (type != EQUALS) {
	switch (type) {
	case DESCRIPTION:
	    type = get_token(fp, token);
	    if (type != QUOTESTRING) {
		print_error("Bad DESCRIPTION", token, type);
		free_node(np);
		return 0;
	    }
#ifdef TEST
	    printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
	    np->description = quoted_string_buffer;
	    quoted_string_buffer = (char *) calloc(1, MAXQUOTESTR);
	    break;

	default:
	    /* NOTHING */
	    break;
	}
	type = get_token(fp, token);
    }
    length = getoid(fp, oid, 32);
    if (length > 1 && length <= 32) {
	/* just take the last pair in the oid list */
	if (oid[length - 2].label)
	    strncpy(np->parent, oid[length - 2].label, MAXLABEL);
	strcpy(np->label, name);
	if (oid[length - 1].subid != -1)
	    np->subid = oid[length - 1].subid;
	else
	    print_error("Warning: This entry is pretty silly", np->label, type);
    } else {
	print_error("No end to oid", (char *) NULL, type);
	free_node(np);
	np = 0;
    }
    /* free oid array */
    for (count = 0; count < length; count++) {
	if (oid[count].label)
	    free(oid[count].label);
	oid[count].label = 0;
    }
    return np;
}

/*
 * Parses a NOTIFICATION-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_notificationDefinition(fp, name)
     FILE *fp;
     char *name;
{
    int type;
    char token[MAXTOKEN];
    int count, length;
    struct subid oid[32];
    struct node *np;

    np = (struct node *) Malloc(sizeof(struct node));
    np->type = 0;
    np->next = 0;
    np->enums = 0;
    np->description = NULL;	/* default to an empty description */
    type = get_token(fp, token);
    while (type != EQUALS) {
	switch (type) {
	case DESCRIPTION:
	    type = get_token(fp, token);
	    if (type != QUOTESTRING) {
		print_error("Bad DESCRIPTION", token, type);
		free_node(np);
		return 0;
	    }
#ifdef TEST
	    printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
	    np->description = quoted_string_buffer;
	    quoted_string_buffer = (char *) calloc(1, MAXQUOTESTR);
	    break;

	default:
	    / BĞ+= m  
È	/*     */ B 4¨NMPT^h */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
     struct snmp_internal_session *isp;
     struct request_list *orp;
{
    struct request_list *rp;
    if (!orp)
	return;
    if (isp->requests == orp) {
	isp->requests = orp->next_request;	/* unlink head */
    } else {
	for (rp = isp->requests; rp; rp = rp->next_request) {
	    if (rp->next_request == orp) {
		rp->next_request = orp->next_request;	/* unlink element */
		break;
	    }
	}
    }
    if (orp->pdu != NULL) {
	snmp_free_pdu(orp->pdu);
    }
    free((char *) orp);
}

#endif/***/ BUG_SNMPTRACE */cked for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù    ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	                                                                    °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
     struct snmp_internal_session *isp;
     struct request_list *orp;
{
    struct request_list *rp;
    if (!orp)
	return;
    if (isp->requests == orp) {
	isp->requests = orp->next_request;	/* unlink head */
    } else {
	for (rp = isp->requests; rp; rp = rp->next_request) {
	    if (rp->next_request == orp) {
		rp->next_request = orp->next_request;	/* unlink element */
		break;
	    }
	}
    }
    if (orp->pdu != NULL) {
	snmp_free_pdu(orp->pdu);
    }
    free((char *) orp);
}
 oid list */
	if (oid[length - 2].label)
	    strncpy(np->parent, oid[length - 2].label, MAXLABEL);
	strcpy(np->label, name);
	if (oid[length - 1].subid != -1)
	    np->subid = oid[length - 1].subid;
	else
	    print_error("Warning: This entry is pretty silly", np->label, type);
    } else {
	print_error("No end to oid", (char *) NULL, type);
	free_node(np);
	np = 0;
    }
    /* free oid array */
    for (count = 0; count < length; count++) {
	if (oid[count].label)
	    free(oid[count].label);
	oid[count].label = 0;
    }
    return np;
}

/*
 * Parses a NOTIFICATION-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_notificationDefinition(fp, name)
     FILE *fp;
     char *name;
{
    int type;
    char token[MAXTOKEN];
    int count, length;
    struct subid oid[32];
    struct node *np;

    np = (struct node *) Malloc(sizeof(struct node));
    np->type = 0;
    np->next = 0;
    np->enums = 0;
    np->description = NULL;	/* default to an empty description */
    type = get_token(fp, token);
    while (type != EQUALS) {
	switch (type) {
	case DESCRIPTION:
	    type = get_token(fp, token);
	    if (type != QUOTESTRING) {
		print_error("Bad DESCRIPTION", token, type);
		free_node(np);
		return 0;
	    }
#ifdef TEST
	    printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
	    np->description = quoted_string_buffer;
	    quoted_string_buffer = (char *) calloc(1, MAXQUOTESTR);
	    break;

	default:
	    / BĞ+= m  
È	/*     */ B 4¨NMPT^h */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                         BĞ+= m  
È	/*     */ B 4¨NMPT—X */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
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
	free((char *) orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int
snmp_close(session)
     struct snmp_session *session;
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
	    free((char *) slp->session->community);
	if (slp->session->peername != NULL)
	    free((char *) slp->session->peername);
	free((char *) slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *) slp->internal);
	free((char *) slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
     u_char *packet;
     int *out_length;
     int is_agent;
{
    u_char buf[PACKET_LENGTH];
    u_char *cp;
    struct variable_list *vp;
    int length;
    int totallength;

    length = *out_length;
    cp = packet;
    for (vp = pdu->variables; vp; vp = vp->next_variable) {
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *) vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *) packet, (char *) cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG) {
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {			/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *) pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char) IPADDRESS,
	    (u_char *) & pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char) TIMETICKS,
	    (long *) &pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *) buf, (char *) cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char) pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *) packet, (char *) cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build(packet, &length, session, is_agent, totallength);
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *) buf, (char *) cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if (session->qoS & USEC_QOS_AUTH)
	md5Digest(packet, totallength, cp - (session->contextLen + 16),
	    cp - (session->contextLen + 16));

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
     u_char *data;
     int length;
{
    u_char msg_type;
    u_char type;
    u_char *var_val;
    long version;
    int len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid objid[MAX_NAME_LEN], *op;
    u_char *origdata = data;
    int origlength = length;
    int ret = 0;
    u_char *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

    if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2) {
	fprintf(stderr, "Wrong version: %ld\n", version);
	return -1;
    }
    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if (session->authenticator) {
	ret = session->authenticator(origdata, origlength, save_data - community_length,
	    community_length, session, pdu);
	if (ret < 0)
	    return ret;
    }
    if (pdu->command != TRP_REQ_MSG) {
	data = asn_parse_int(data, &length, &type, (long *) &pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *) calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *) objid, (char *) pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *) & pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while ((int) length > 0) {
	if (pdu->variables == NULL) {
	    pdu->variables = vp = (struct variable_list *) calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *) calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *) &length);
	if (data == NULL)
	    return -1;
	op = (oid *) calloc(1, (unsigned) vp->name_length * sizeof(oid));
	bcopy((char *) objid, (char *) op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch ((short) vp->type) {
	case ASN_INTEGER:
	    vp->val.integer = (long *) calloc(1, sizeof(long));
	    vp->val_len = sizeof(long);
	    asn_parse_int(var_val, &len, &vp->type, (long *) vp->val.integer, sizeof(vp->val.integer));
	    break;
	case COUNTER:
	case GAUGE:
	case TIMETICKS:
	case UINTEGER:
	    vp->val.integer = (long *) calloc(1, sizeof(unsigned long));
	    vp->val_len = sizeof(unsigned long);
	    asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *) vp->val.integer, sizeof(vp->val.integer));
	    break;
	case COUNTER64:
	    vp->val.counter64 = (struct counter64 *) calloc(1, sizeof(struct counter64));
	    vp->val_len = sizeof(struct counter64);
	    asn_parse_unsigned_int64(var_val, &len, &vp->type,
		(struct counter64 *) vp->val.counter64,
		sizeof(*vp->val.counter64));
	    break;
	case ASN_OCTET_STR:
	case IPADDRESS:
	case OPAQUE:
	case NSAP:
	    vp->val.string = (u_char *) calloc(1, (unsigned) vp->val_len);
	    asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
	    break;
	case ASN_OBJECT_ID:
	    vp->val_len = MAX_NAME_LEN;
	    asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
	    vp->val_len *= sizeof(oid);
	    vp->val.objid = (oid *) calloc(1, (unsigned) vp->val_len);
	    bcopy((char *) objid, (char *) vp->val.objid, vp->val_len);
	    break;
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
	case ASN_NULL:
	    break;
	default:
	    fprintf(stderr, "bad type returned (%x)\n", vp->type);
	    break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for (slp = Sessions; slp; slp = slp->next) {
	if (slp->session == session) {
	    isp = slp->internal;
	    break;
	}
    }

    if (!pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (isp == NULL) {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG
	|| pdu->command == GETBULK_REQ_MSG) {
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
	    pdu->enterprise = (oid *) calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *) DEFAULT_ENTERPRISE, (char *) pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE) / sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS) {
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS) {
	    bcopy((char *) &isp->addr, (char *) &pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
    if (snmp_build(session, pdu, packet, &length, 0) < 0) {
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {			/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *) pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char) IPADDRESS,
	    (u_char *) & pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char) TIMETICKS,
	    (long *) &pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *) buf, (char *) cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char) pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *) packet, (char *) cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build(packet, &length, session, is_agent, totallength);
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *) buf, (char *) cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if (session->qoS & USEC_QOS_AUTH)
	md5Digest(packet, totallength, cp - (session->contextLen + 16),
	    cp - (session->contextLen + 16));

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
     u_char *data;
     int length;
{
    u_char msg_type;
    u_char type;
    u_char *var_val;
    long version;
    int len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid objid[MAX_NAME_LEN], *op;
    u_char *origdata = data;
    int origlength = length;
    int ret = 0;
    u_char *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

    if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2) {
	fprintf(stderr, "Wrong version: %ld\n", version);
	return -1;
    }
    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if (session->authenticator) {
	ret = session->authenticator(origdata, origlength, save_data - community_length,
	    community_length, session, pdu);
	if (ret < 0)
	    return ret;
    }
    if (pdu->command != TRP_REQ_MSG) {
	data = asn_parse_int(data, &length, &type, (long *) &pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *) calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *) objid, (char *) pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *) & pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *) &pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while ((int) length > 0) {
	if (pdu->variables == NULL) {
	    pdu->variables = vp = (struct variable_list *) calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *) calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *) &length);
	if (data == NULL)
	    return -1;
	op = (oid *) calloc(1, (unsigned) vp->name_length * sizeof(oid));
	bcopy((char *) objid, (char *) op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch ((short) vp->type) {
	case ASN_INTEGER:
	    vp->val.integer = (long *) calloc(1, sizeof(long));
	    vp->val_len = sizeof(long);
	    asn_parse_int(var_val, &len, &vp->type, (long *) vp->val.integer, sizeof(vp->val.integer));
	    break;
	case COUNTER:
	case GAUGE:
	case TIMETICKS:
	case UINTEGER:
	    vp->val.integer = (long *) calloc(1, sizeof(unsigned long));
	    vp->val_len = sizeof(unsigned long);
	    asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *) vp->val.integer, sizeof(vp->val.integer));
	    break;
	case COUNTER64:
	    vp->val.counter64 = (struct counter64 *) calloc(1, sizeof(struct counter64));
	    vp->val_len = sizeof(struct counter64);
	    asn_parse_unsigned_int64(var_val, &len, &vp->type,
		(struct counter64 *) vp->val.counter64,
		sizeof(*vp->val.counter64));
	    break;
	case ASN_OCTET_STR:
	case IPADDRESS:
	case OPAQUE:
	case NSAP:
	    vp->val.string = (u_char *) calloc(1, (unsigned) vp->val_len);
	    asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
	    break;
	case ASN_OBJECT_ID:
	    vp->val_len = MAX_NAME_LEN;
	    asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
	    vp->val_len *= sizeof(oid);
	    vp->val.objid = (oid *) calloc(1, (unsigned) vp->val_len);
	    bcopy((char *) objid, (char *) vp->val.objid, vp->val_len);
	    break;
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
	case ASN_NULL:
	    break;
	default:
	    fprintf(stderr, "bad type returned (%x)\n", vp->type);
	    break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for (slp = Sessions; slp; slp = slp->next) {
	if (slp->session == session) {
	    isp = slp->internal;
	    break;
	}
    }

    if (!pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (isp == NULL) {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG
	|| pdu->command == GETBULK_REQ_MSG) {
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
	    pdu->enterprise = (oid *) calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *) DEFAULT_ENTERPRISE, (char *) pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE) / sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS) {
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS) {
	    bcopy((char *) &isp->addr, (char *) &pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
    if (snmp_build(session, pdu, packet, &length, 0) < 0) {
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
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
	free((char *) orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int
snmp_close(session)
     struct snmp_session *session;
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
	    free((char *) slp->session->community);
	if (slp->session->peername != NULL)
	    free((char *) slp->session->peername);
	free((char *) slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *) slp->internal);
	free((char *) slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
     struct snmp_session *session;
     struct snmp_pdu *pdu;
     u_char *packet;
     int *out_length;
     int is_agent;
{
    u_char buf[PACKET_LENGTH];
    u_char *cp;
    struct variable_list *vp;
    int length;
    int totallength;

    length = *out_length;
    cp = packet;
    for (vp = pdu->variables; vp; vp = vp->next_variable) {
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *) vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *) packet, (char *) cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG) {
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *) &pdu-> BĞ+= m  
È	/*  >X*/ B 4¨NMPT˜à */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
	if (snmp_dump_packet) {
	snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ ‚àÿ¶·    ÿ¶Ù 4¨ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	     snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
	if (snmp_dump_packet) {
	snmp_print_packet(packet, length, pdu->address, 1);
    }
MUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct BĞ+= m  
È	/*     */ B >XNMPTÊ  */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

	gettimeofday(&tv, (struct timezone *) 0);
    if (sendto(isp->sd, (char *) packet, length, 0, (struct sockaddr *) &pdu->address, sizeof(pdu->address)) < 0) {
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG) {
	/* set up to expect a response */
	rp = (struct request_list *) calloc(1, sizeof(struct request_list));
#if 1/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù 4¨ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    ables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

	gettimeofday(&tv, (struct timezone *) 0);
    if (sendto(isp->sd, (char *) packet, length, 0, (struct sockaddr *) &pdu->address, sizeof(pdu->address)) < 0) {
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG) {
	/* set up to expect a response */
	rp = (struct request_list *) calloc(1, sizeof(struct request_list));
ar *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->vari BĞ+= m  
È	/*  4¨*/ B    NMPTÊ  */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
	    if (!rp) {
	    fprintf(stderr, "Out of memory!\n");
	    snmp_errno = SNMPERR_GENERR;
	    return 0;
	}
#endif/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    e SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
	    if (!rp) {
	    fprintf(stderr, "Out of memory!\n");
	    snmp_errno = SNMPERR_GENERR;
	    return 0;
	}
ULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            cas BĞ+= m  
È	/*  >X*/ B 4¨NMPTË° */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu *pdu)
{
    struct variable_list *vp, *ovp;

    if (!pdu)
	return;

    vp = pdu->variables;
    while (vp) {
	if (vp->name) {
	    free((char *) vp->name);
	}
	if (vp->val.string) {
	    free((char *) vp->val.string);
	}
	ovp = vp;
	vp = vp->next_variable;
	free((char *) ovp);
    }
    if (pdu->enterprise) {
	free((char *) pdu->enterprise);
    }
    free((char *) pdu);
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
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for (slp = Sessions; slp; slp = slp->next) {
	if (FD_ISSET(slp->internal->sd, fdset)) {
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *) packet, PACKET_LENGTH, 0, (struct sockaddr *) &from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù 4¨ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu *pdu)
{
    struct variable_list *vp, *ovp;

    if (!pdu)
	return;

    vp = pdu->variables;
    while (vp) {
	if (vp->name) {
	    free((char *) vp->name);
	}
	if (vp->val.string) {
	    free((char *) vp->val.string);
	}
	ovp = vp;
	vp = vp->next_variable;
	free((char *) ovp);
    }
    if (pdu->enterprise) {
	free((char *) pdu->enterprise);
    }
    free((char *) pdu);
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
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for (slp = Sessions; slp; slp = slp->next) {
	if (FD_ISSET(slp->internal->sd, fdset)) {
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *) packet, PACKET_LENGTH, 0, (struct sockaddr *) &from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
ponse->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid); BĞ+= m  
È	/*  4¨*/ B    NMPTÍ8 */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
		if (snmp_dump_packet) {
		snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *) calloc(1, sizeof(struct snmp_pdu));

	    if (!pdu) {
		fprintf(stderr, "Out of memory!\n");
		snmp_errno = SNMPERR_GENERR;
		return;
	    }
#endif/***/ if we found entry that points here */
 oslp e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ ‚àÿ¶·    ÿ¶Ù 4¨ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	       pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
		if (snmp_dump_packet) {
		snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *) calloc(1, sizeof(struct snmp_pdu));

	    if (!pdu) {
		fprintf(stderr, "Out of memory!\n");
		snmp_errno = SNMPERR_GENERR;
		return;
	    }
 == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	  BĞ+= m  
È	/*     */ B >XNMPTÔè */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

		pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0) {
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }
	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG) {
#if 1 /***/			/* bug fix: illegal re-use of rp killed some requests */
		struct request_list *rp_next = 0;
		for (rp = isp->requests; rp; rp = rp_next) {
		    rp_next = rp->next_request;
		    if (rp->request_id == pdu->reqid) {
#if DEBUG_SNMPTRACE
			snmp_print_trace(slp, rp, TRACE_RECV);
#endif
			if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1) {
			    /* successful, so delete request */
			    free_one_request(isp, rp);
			    break;	/* no more request with the same reqid */
			}
		    }
		}
#endif/***/ g fix: illegal re-use of rp killed some requests */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

		pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0) {
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }
	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG) {
#if 1 /***/			/* bug fix: illegal re-use of rp killed some requests */
		struct request_list *rp_next = 0;
		for (rp = isp->requests; rp; rp = rp_next) {
		    rp_next = rp->next_request;
		    if (rp->request_id == pdu->reqid) {
#if DEBUG_SNMPTRACE
			snmp_print_trace(slp, rp, TRACE_RECV);
#endif
			if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1) {
			    /* successful, so delete request */
			    free_one_request(isp, rp);
			    break;	/* no more request with the same reqid */
			}
		    }
		}
>pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *) BĞ+= m  
È	/*  >X*/ B 7 NMPTÔè */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		|| pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG) {
#if DEBUG_SNMPTRACE
		snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
		sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
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
	if (isp->requests) {
	    /* found another session with outstanding requests */
	    requests++;
	    for (rp = isp->requests; rp; rp = rp->next_request) {
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
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
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/			/* replacing freeme by simpler and safer rp_next */
    struct request_list *rp, *rp_next = 0;
#endif/***/ placing freeme by simpler and safer rp_next*/n s */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù 0¸ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	     a failure occured.
 */
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		|| pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG) {
#if DEBUG_SNMPTRACE
		snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
		sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
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
	if (isp->requests) {
	    /* found another session with outstanding requests */
	    requests++;
	    for (rp = isp->requests; rp; rp = rp->next_request) {
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
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
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/			/* replacing freeme by simpler and safer rp_next */
    struct request_list *rp, *rp_next = 0;
  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
}

/*
 * Sends the input pdu on the session after calling snmp_build to create
 * a serialized packet.  If necessary, set some of the pdu data from the
 * session defaults.  Add a request corresponding to this pdu to the list
 * of outstanding requests on this session, then send the pdu.
 * Returns the request id of the generated packet if applicable, otherwise 1.
 * On any error, 0 is returned.
 * The pdu is freed by snmp_send() unless BĞ+= m  
È	/*  0¸*/ B    NMPTÙˆ */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
	struct timeval now;

    gettimeofday(&now, (struct timezone *) 0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for (slp = Sessions; slp; slp = slp->next) {
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/			/* simplification */
	for (rp = isp->requests; rp; rp = rp_next) {
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)) {
		/* this timer has expired */
		if (rp->retries >= sp->retries) {
#if DEBUG_SNMPTRACE
		    snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		    /* No more chances, delete this entry */
		    sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		    free_one_request(isp, rp);
		    continue;
#endif/***/ mplification */by simpler and safer rp_next*/n s */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    h)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
	struct timeval now;

    gettimeofday(&now, (struct timezone *) 0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for (slp = Sessions; slp; slp = slp->next) {
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/			/* simplification */
	for (rp = isp->requests; rp; rp = rp_next) {
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)) {
		/* this timer has expired */
		if (rp->retries >= sp->retries) {
#if DEBUG_SNMPTRACE
		    snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		    /* No more chances, delete this entry */
		    sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		    free_one_request(isp, rp);
		    continue;
r *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, lengt BĞ+= m  
È	/*  >X*/ B 3NMPTèè */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0) {
			fprintf(stderr, "Error building packet\n");
		    }
#if 1/***/ mplification */by simpler and safer rp_next*/n s */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    ;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0) {
			fprintf(stderr, "Error building packet\n");
		    }
 the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return BĞ+= m  
È	/*  >X*/ B 4¨NMPTì  */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
#if 1 /***/
			if (snmp_dump_packet) {
			snmp_print_packet(packet, length, rp->pdu->address, 1);
		    }
#endif/***/ mplification */by simpler and safer rp_next*/n s */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ ‚àÿ¶·    ÿ¶Ù 4¨ÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
#if 1 /***/
			if (snmp_dump_packet) {
			snmp_print_packet(packet, length, rp->pdu->address, 1);
		    }
 If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter BĞ+= m  
È	/*     */ B >XNMPTíˆ */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
#if 1 /***/
		    if (snmp_dump_packet){
		      snmp_print_packet(packet, length, rp->pdu->address, 1);
		    }
#endif /***/
			gettimeofday(&tv, (struct timezone *) 0);
		    if (sendto(isp->sd, (char *) packet, length, 0, (struct sockaddr *) &rp->pdu->address, sizeof(rp->pdu->address)) < 0) {
			perror("sendto");
		    }
		    rp->time = tv;
		    tv.tv_usec += rp->timeout;
		    tv.tv_sec += tv.tv_usec / 1000000L;
		    tv.tv_usec %= 1000000L;
		    rp->expire = tv;
#if DEBUG_SNMPTRACE
		    snmp_print_trace(slp, rp, TRACE_SEND);
#endif
		}
	    }
#if 1 /***/			/* simplification */
	}
#endif/***/ mplification */by simpler and safer rp_next*/n s */ replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ    ÿ¶·    ÿ¶Ù ‚àÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @	    000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
#if 1 /***/
		    if (snmp_dump_packet){
		      snmp_print_packet(packet, length, rp->pdu->address, 1);
		    }
#endif /***/
			gettimeofday(&tv, (struct timezone *) 0);
		    if (sendto(isp->sd, (char *) packet, length, 0, (struct sockaddr *) &rp->pdu->address, sizeof(rp->pdu->address)) < 0) {
			perror("sendto");
		    }
		    rp->time = tv;
		    tv.tv_usec += rp->timeout;
		    tv.tv_sec += tv.tv_usec / 1000000L;
		    tv.tv_usec %= 1000000L;
		    rp->expire = tv;
#if DEBUG_SNMPTRACE
		    snmp_print_trace(slp, rp, TRACE_SEND);
#endif
		}
	    }
#if 1 /***/			/* simplification */
	}
ata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1 BĞ+= m  
È	/*  >X*/ B 4¨NMPTíˆ */c    for testing purposes */e key!  replace...
     */
 *                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ÿ¯ùsnmplib/snmp_api.c c  .h   ÿ°… <Ğlib/snmp_api.c~ ~  ñ   ÿ± <ğÿ±Fÿ±Yÿ±iÿ±{ÿ±Š   ÿ±« =ÿ±Çÿ±Óÿ±éÿ±÷ÿ²   ÿ² =0ÿ²<ÿ²Kÿ²Wÿ²fÿ²t   ÿ²Š =Pÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ã   ÿ³
 =pÿ³3ÿ³Bÿ³Sÿ³]ÿ³i   ÿ³‚   ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×   Áÿ³ù   ÿ´ =ø %     D(   ÿ´_ =à  \     BØ   ÿ´© =˜  4     BØ   ÿ´ø =È  H     BØ   ÿµB >ÿµ]ÿµmÿµz   ÿµ  >(ÿµ·ÿµÉÿµÖ   ÿµï >@ÿ¶ÿ¶ ÿ¶4   ÿ¶P   ÿ¶rÿ¶~ÿ¶ˆ   0ÿ¶Ÿ 4¨ÿ¶·    ÿ¶Ù ‰èÿ·    ÿ·#ÿ·/ÿ·> >Xÿ·V   3    /usr/people/wessels/.indent.pro                       ÿ¯èÿ¯ùÿ°ÿ°ÿ°.ÿ°?ÿ°Mÿ°[ÿ°pÿ°…ÿ°•ÿ°£ÿ°²ÿ°Åÿ°Ûÿ°ñÿ±
ÿ±ÿ±2ÿ±Fÿ±Yÿ±iÿ±{ÿ±Šÿ±™ÿ±«ÿ±ºÿ±Çÿ±Óÿ±éÿ±÷ÿ²ÿ²ÿ²ÿ²2ÿ²<ÿ²Kÿ²Wÿ²fÿ²tÿ²ÿ²Šÿ²™ÿ²¨ÿ²¶ÿ²Äÿ²Ôÿ²ãÿ²öÿ³
ÿ³ ÿ³3ÿ³Bÿ³Sÿ³]ÿ³iÿ³sÿ³‚ÿ³‘ÿ³ ÿ³­ÿ³ºÿ³Êÿ³×ÿ³çÿ³ùÿ´ÿ´ÿ´ÿ´)ÿ´3ÿ´Cÿ´Oÿ´_ÿ´kÿ´tÿ´ÿ´ÿ´Ÿÿ´©ÿ´·ÿ´Åÿ´Òÿ´İÿ´íÿ´øÿµÿµÿµÿµ)ÿµ7ÿµBÿµMÿµ]ÿµmÿµzÿµ‰ÿµ ÿµ«ÿµ·ÿµÉÿµÖÿµâÿµïÿ¶ÿ¶ÿ¶ ÿ¶4ÿ¶?ÿ¶Pÿ¶bÿ¶rÿ¶~ÿ¶ˆÿ¶”ÿ¶Ÿÿ¶«ÿ¶·ÿ¶Éÿ¶Ùÿ¶íÿ·ÿ·ÿ·#ÿ·/ÿ·>ÿ·Lÿ·Vÿ·fÿ·q                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        °           >X    4¨                                                    $                  @             ,    2ˆ           …     >X             ‚à      C             0                              ¸ude/snmp_groupvars.h~              àude/snmp_groupvars.h                 X                                     €                                     ¨                                     Ğ                                                                     „©    /***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */
#define DEBUG_SNMPTRACE		0 /* set to 1 to print all SNMP actions */
#define DEBUG_SNMPFULLDUMP	0 /* set to 1 to dump all SNMP packets */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef linux
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define PACKET_LENGTH	4500

#ifndef BSD4_3
#define BSD4_2
#endif

#if !defined(BSD4_3) && !defined(linux) && !defined(sun)

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1}; /* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0
#define DEFAULT_MMS	    1389 /* large, randomly picked for testing purposes */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    u_long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request (saved so it can be retransmitted */
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

u_long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};


void sync_with_agent();
int parse_app_community_string();
void snmp_synch_setup();
int snmp_synch_response();
void md5Digest();


static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION && snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}

#if 0
/*
 * Gets initial request ID for all transactions.
 */
static void
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}
#endif


/*
 * Dump snmp packet to stdout:
 */
static void
snmp_print_packet(packet, length, addr, code)
  char *packet; 
  int length; 
  ipaddr addr; 
  int code;
{
  if(length < 0) {
    return;
  }
  if (code <= 0) { /* received */
    printf("\nReceived %4d bytes from ", length);
  }
  else { /* sending */
    printf("\nSending  %4d bytes to   ", length);
  }
  printf("%s:", inet_ntoa(addr.sin_addr));
#if DEBUG_SNMPFULLDUMP
  for (count = 0; count < length; count++) {
    if ((count & 15) == 0) {
      printf("\n  ");
    }
    printf("%02X ", (int)(packet[count]&255));
  }
#endif
  fflush(stdout);
}

#if DEBUG_SNMPTRACE
/*
 * Print request
 */
#define TRACE_SEND   (0)
#define TRACE_RECV   (1)
#define TRACE_TIMEOUT (2)
static void
snmp_print_trace(slp, rp, code)
  struct session_list *slp;
  struct request_list *rp;
  int code;
{
  int reqid=0, retries=1;
  if( rp ){
    reqid = rp->request_id;
    retries = rp->retries;
  }  
  printf("\n Session %2d  ReqId %4d  ", slp->internal->sd, reqid);
  switch(code)
    { 
    case TRACE_SEND:    printf("send pdu (%d)", retries);break; 
    case TRACE_RECV:    printf("recv pdu");break; 
    case TRACE_TIMEOUT: printf("time out");break; 
    }
  fflush(stdout);
}
#endif /* DEBUG_SNMPTRACE */




/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;
    extern int check_received_pkt();

    /* Copy session structure and link into list */
    slp = (struct session_list *)calloc(1, sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)calloc(1, sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)calloc(1, sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)calloc(1, (unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = SNMP_API_DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = SNMP_API_DEFAULT_TIMEOUT;
    if (session->MMS == 0 )
	session->MMS = DEFAULT_MMS;
    isp->requests = NULL;


    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	if( *session->community == '+' ) {
		session->community_len--;
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community+1, (char *)cp,
		      session->community_len);
		session->version = SNMP_VERSION_2C;
	} else {
		cp = (u_char *) calloc(1, (unsigned) session->community_len);
		bcopy((char *) session->community, (char *) cp, 
		      session->community_len);
	}

    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)calloc(1, (unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;

    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    /*servp = getservbyname("snmp", "udp");*/
	    servp=NULL;
	    if (servp != NULL){
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

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (! snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n", 
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }

    if( *cp == '/' ) {
	session->authenticator = check_received_pkt;
	sync_with_agent(session);
	parse_app_community_string( session );
	session->qoS |= USEC_QOS_GENREPORT;
    }

    /* replace comm pointer with pointer to new data: */
    session->community = cp;	

    return session;
}

void
sync_with_agent( session )
struct snmp_session *session;
{
    struct snmp_pdu *pdu, *response = 0;
    int status;

    session->qoS = USEC_QOS_GENREPORT;
    session->userLen = 6;
    session->version = SNMP_VERSION_2;
    strcpy( session->userName, "public" );

    snmp_synch_setup(session);
    pdu = snmp_pdu_create(GET_REQ_MSG);
    status = snmp_synch_response(session, pdu, &response);

    if (status == STAT_SUCCESS){
	memcpy( session->agentID, response->params.agentID, 12 );

	/* save the clocks -- even though they are not authentic */
	session->agentBoots = response->params.agentBoots;
	session->agentTime = response->params.agentTime;
	session->agentClock = response->params.agentTime - time(NULL);

    } else {
	    if (status == STAT_TIMEOUT){
		printf("No Response from %s\n", session->peername);
	    } else {    /* status == STAT_ERROR */
		printf("An error occurred, Quitting\n");
	    }
	    exit( -1 );
    }

    /** freed to early: 
      snmp_free_pdu(pdu);
      if (response) snmp_free_pdu(response);
     **/
}
#if 1 /***/
/*
 * Unlink one element from input request list,
 * then free it and it's pdu.
 */
static void
free_one_request(isp, orp)
    struct snmp_internal_session *isp;
    struct request_list *orp;
{
    struct request_list *rp;
    if(! orp) return;
    if(isp->requests == orp){ 
      isp->requests = orp->next_request; /* unlink head */
    }
    else{
      for(rp = isp->requests; rp; rp = rp->next_request){
        if(rp->next_request == orp){ 
	  rp->next_request = orp->next_request; /* unlink element */
	  break;
        }
      }
    }
    if (orp->pdu != NULL){
      snmp_free_pdu(orp->pdu);
    }
    free((char *)orp);
}
#endif /***/
/*
 * Free each element in the input request list.
 */
static void
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length, is_agent)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    u_char	*packet;
    int			*out_length;
    int			 is_agent;
{
    u_char  buf[PACKET_LENGTH];
    u_char  *cp;
    struct variable_list *vp;
    int	    length;
    int	    totallength;

    length = *out_length;
    cp = packet;
    for(vp = pdu->variables; vp; vp = vp->next_variable){
	cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type, vp->val_len, (u_char *)vp->val.string, &length);
	if (cp == NULL)
	    return -1;
    }
    totallength = cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), totallength);
    if (cp == NULL)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;
    if (pdu->command != TRP_REQ_MSG){
	/* request id */
	cp = asn_build_int(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (cp == NULL)
	    return -1;
	/* error status */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errstat, sizeof(pdu->errstat));
	if (cp == NULL)
	    return -1;
	/* error index */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->errindex, sizeof(pdu->errindex));
	if (cp == NULL)
	    return -1;
    } else {	/* this is a trap message */
	/* enterprise */
	cp = asn_build_objid(packet, &length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    (oid *)pdu->enterprise, pdu->enterprise_length);
	if (cp == NULL)
	    return -1;
	/* agent-addr */
	cp = asn_build_string(cp, &length, (u_char)IPADDRESS,
		(u_char *)&pdu->agent_addr.sin_addr.s_addr, sizeof(pdu->agent_addr.sin_addr.s_addr));
	if (cp == NULL)
	    return -1;
	/* generic trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (cp == NULL)
	    return -1;
	/* specific trap */
	cp = asn_build_int(cp, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (cp == NULL)
	    return -1;
	/* timestamp  */
	cp = asn_build_int(cp, &length, (u_char)TIMETICKS,
		(long *)&pdu->time, sizeof(pdu->time));
	if (cp == NULL)
	    return -1;
    }
    if (length < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;

    length = PACKET_LENGTH;
    cp = asn_build_header(buf, &length, (u_char)pdu->command, totallength);
    if (cp == NULL)
	return -1;
    if (length < totallength)
	return -1;
    bcopy((char *)packet, (char *)cp, totallength);
    totallength += cp - buf;

    length = *out_length;

    cp = snmp_auth_build( packet, &length, session, is_agent, totallength );
    if (cp == NULL)
	return -1;
    if ((*out_length - (cp - packet)) < totallength)
	return -1;
    bcopy((char *)buf, (char *)cp, totallength);
    totallength += cp - packet;
    *out_length = totallength;

    if( session->qoS & USEC_QOS_AUTH )
	    md5Digest( packet, totallength, cp - (session->contextLen + 16),
		cp - (session->contextLen + 16) );

    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[256];
    int community_length = 256;
    struct variable_list *vp = 0;
    oid	    objid[MAX_NAME_LEN], *op;
    u_char  *origdata = data;
    int      origlength = length;
    int      ret = 0;
    u_char  *save_data;

    /* authenticates message and returns length if valid */
    data = snmp_auth_parse(data, &length, community, &community_length, &version);
    if (data == NULL)
	return -1;

   if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2C && version != SNMP_VERSION_2 ) {
	    fprintf(stderr, "Wrong version: %ld\n", version);
	    return -1;
    }

    save_data = data;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    if( session->authenticator ) {
	ret = session->authenticator( origdata, origlength, save_data - community_length, 
		community_length, session, pdu );
	if( ret < 0 ) return ret;
    }

    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, (long *)&pdu->reqid, sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errstat, sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->errindex, sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid, &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)calloc(1, pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise, pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type, (u_char *)&pdu->agent_addr.sin_addr.s_addr, &four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type, sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type, sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->time, sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    pdu->variables = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	} else {
	    vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
	    vp = vp->next_variable;
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type, &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;
	op = (oid *)calloc(1, (unsigned)vp->name_length * sizeof(oid));
	bcopy((char *)objid, (char *)op, vp->name_length * sizeof(oid));
	vp->name = op;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(long));
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type, (long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)calloc(1, sizeof(unsigned long));
		vp->val_len = sizeof(unsigned long);
		asn_parse_unsigned_int(var_val, &len, &vp->type, (unsigned long *)vp->val.integer, sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)calloc(1,  sizeof(struct counter64) );
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		vp->val.string = (u_char *)calloc(1, (unsigned)vp->val_len);
		asn_parse_string(var_val, &len, &vp->type, vp->val.string, &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)calloc(1, (unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return ret;
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
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }

    if (! pdu) {
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }

    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG 
	|| pdu->command == GETBULK_REQ_MSG ){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else {
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)calloc(1, sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise, sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address, sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	

    if (snmp_build(session, pdu, packet, &length, 0) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
#if 1 /***/
    if (snmp_dump_packet){
      snmp_print_packet(packet, length, pdu->address, 1);
    }
#endif /***/

    gettimeofday(&tv, (struct timezone *)0);
    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG 
     || pdu->command == SET_REQ_MSG || pdu->command == GETBULK_REQ_MSG ){
	/* set up to expect a response */
	rp = (struct request_list *)calloc(1, sizeof(struct request_list));
#if 1 /***/
        if(! rp){
          fprintf(stderr, "Out of memory!\n");
          snmp_errno = SNMPERR_GENERR;
          return 0;
        }
#endif /***/
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
#if DEBUG_SNMPTRACE
	snmp_print_trace(slp, rp, TRACE_SEND);
#endif
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu * pdu)
{
    struct variable_list *vp, *ovp;

    if (! pdu)
      return;

    vp = pdu->variables;
    while(vp){
      if (vp->name) {
	free((char *)vp->name);
      }
      if (vp->val.string) {
	free((char *)vp->val.string);
      }
      ovp = vp;
      vp = vp->next_variable;
      free((char *)ovp);
    }
    if (pdu->enterprise) {
      free((char *)pdu->enterprise);
    }
    free((char *)pdu);
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
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    ssize_t length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp /**, *orp **/ ;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof(from);
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0, (struct sockaddr *)&from, &fromlength);
	    if (length == -1) {
		perror("recvfrom");
		return;
	    }
#if 1 /***/
	    if (snmp_dump_packet){
	      snmp_print_packet(packet, length, from, 0);
	    }
	    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));

	    if(! pdu){
	      fprintf(stderr, "Out of memory!\n");
	      snmp_errno = SNMPERR_GENERR;
	      return;
	    }
#endif /***/

	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) < 0){
		fprintf(stderr, "Mangled packet\n");
		snmp_free_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG){
#if 1 /***/ /* bug fix: illegal re-use of rp killed some requests */
	      struct request_list *rp_next= 0;
	      for(rp = isp->requests; rp; rp = rp_next){
		rp_next = rp->next_request;
		if (rp->request_id == pdu->reqid){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_RECV);
#endif
		  if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic) == 1){
		    /* successful, so delete request */
		    free_one_request(isp, rp);
		    break;  /* no more request with the same reqid */
		  }
		}
	      }
#endif /***/
	    } else if (pdu->command == GET_REQ_MSG 
		    || pdu->command == GETNEXT_REQ_MSG
		    || pdu->command == GETBULK_REQ_MSG
		    || pdu->command == TRP_REQ_MSG || pdu->command == SET_REQ_MSG){
#if DEBUG_SNMPTRACE
	      snmp_print_trace(slp, NULL, TRACE_RECV);
#endif
	      sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu, sp->callback_magic);
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
 * Block is 1 if the select is requested to block indefinitely, rather
 * than time out.  If block is input as 1, the timeout value will be
 * treated as undefined, but it must be available for setting in
 * snmp_select_info.  On return, if block is true, the value of
 * timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The
 * number of sessions open) 
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives (i.e. no input) */
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
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/* 
 * snmp_timeout should be called whenever the timeout from
 * snmp_select_info expires, but it is idempotent, so snmp_timeout can
 * be polled (probably a cpu expensive proposition).  snmp_timeout
 * checks to see if any of the sessions have an outstanding request
 * that has timed out.  If it finds one (or more), and that pdu has
 * more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for
 * the session is used to alert the user of the timeout.
 */
void
snmp_timeout()
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
#if 1 /***/ /* replacing freeme by simpler and safer rp_next*/
    struct request_list *rp, *rp_next = 0;
#endif /***/
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
#if 1 /***/ /* simplification */
	for(rp = isp->requests; rp; rp = rp_next){
	    rp_next = rp->next_request;
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
#if DEBUG_SNMPTRACE
		  snmp_print_trace(slp, rp, TRACE_TIMEOUT);
#endif
		  /* No more chances, delete this entry */
		  sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, sp->callback_magic);
		  free_one_request(isp, rp);
		  continue;
#endif /***/
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    rp->timeout <<= 1;
		    if (snmp_build(sp, rp->pdu, packet, &length, 0) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
#if 1 /***/
		    if (snmp_dump_packet){
		      snmp_print_packet(packet, length, rp->pdu->address, 1);
		    }
#endif /***/
		    gettimeofday(&tv, (struct timezone *)0);
		    if (sendto(isp->sd, (char *)packet, length, 0, (struct sockaddr *)&rp->pdu->address, sizeof(rp->pdu->address)) < 0){
			perror("sendto");
		    }
		    rp->time = tv;
		    tv.tv_usec += rp->timeout;
		    tv.tv_sec += tv.tv_usec / 1000000L;
		    tv.tv_usec %= 1000000L;
		    rp->expire = tv;
#if DEBUG_SNMPTRACE
		    snmp_print_trace(slp, rp, TRACE_SEND);
#endif
		}
	    }
#if 1 /***/ /* simplification */
	}
#endif /***/
    }
}
