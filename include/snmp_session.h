/* -*- c++ -*- */
#ifndef SQUID_SNMP_SESSION_H
#define SQUID_SNMP_SESSION_H

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
 * $Id: snmp_session.h,v 1.4 2001/10/17 19:05:37 hno Exp $
 * 
 **********************************************************************/

struct snmp_session {
    int Version;		/* SNMP Version for this session */


    u_char *community;		/* community for outgoing requests. */
    int community_len;		/* Length of community name. */
    int retries;		/* Number of retries before timeout. */
    int timeout;		/* Number of uS until first timeout, then exponential backoff */
    char *peername;		/* Domain name or dotted IP address of default peer */
    u_short remote_port;	/* UDP port number of peer. */
    u_short local_port;		/* My UDP port number, 0 for default, picked randomly */
};

#define RECEIVED_MESSAGE   1
#define TIMED_OUT	   2

#endif /* SQUID_SNMP_SESSION_H */
