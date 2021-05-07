/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_API_UTIL_H
#define SQUID_SNMP_API_UTIL_H

/* NP: required for typedef ipaddr */
#include "snmp_pdu.h"

/***********************************************************
    Copyright 1997 by Carnegie Mellon University

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
 * snmp_api_util.h - API management.
 * Didier DESIDERIO (SINFOR) - November 26th, 1997
 */

#define PACKET_LENGTH 4500

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    int request_id;     /* request id */
    int retries;        /* Number of retries */
    u_int timeout;      /* length to wait for timeout */
    struct timeval time;    /* Time this request was made */
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

struct snmp_internal_session {
    int sd;         /* socket descriptor for this connection */
    struct sockaddr_in addr;        /* address of connected peer */
    struct request_list *requests;  /* Info about outstanding requests */
};

/* Define these here, as they aren't defined normall under
 * cygnus Win32 stuff.
 */
#undef timercmp
#define timercmp(tvp, uvp, cmp)         \
  (((tvp)->tv_sec) cmp ((uvp)->tv_sec)) ||  \
  ((((tvp)->tv_sec) == ((uvp)->tv_sec)) &&  \
   (((tvp)->tv_usec) cmp ((uvp)->tv_usec)))

#undef timerclear
#define timerclear(tvp) (tvp)->tv_sec = (tvp)->tv_usec = 0

#undef timerisset
#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)

#if HAVE_SRAND
#define random rand
#define srandom srand
#endif /* HAVE_SRAND */

#ifdef __cplusplus
extern "C" {
#endif

int snmp_get_socket_session(struct snmp_session *session_);
int snmp_select_info_session(struct snmp_session *session_, struct timeval *timeout);
int snmp_timeout_session(struct snmp_session *sp_);

#ifdef __cplusplus
}

#endif

#endif              /* SQUID_SNMP_API_UTIL_H */

