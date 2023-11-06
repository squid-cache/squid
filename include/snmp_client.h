/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_CLIENT_H
#define SQUID_SNMP_CLIENT_H

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
struct synch_state {
    int waiting;
    int status;
    /* status codes */
#define STAT_SUCCESS    0
#define STAT_ERROR  1
#define STAT_TIMEOUT 2
    int reqid;
    struct snmp_pdu *pdu;
};

#ifdef __cplusplus
extern "C" {
#endif

extern struct synch_state snmp_synch_state;

/* Synchronize Input with Agent */
int snmp_synch_input(int, struct snmp_session *, int,
                     struct snmp_pdu *, void *);

/* Synchronize Response with Agent */
int snmp_synch_response(struct snmp_session *, struct snmp_pdu *,
                        struct snmp_pdu **);

/* Synchronize Setup */
void snmp_synch_setup(struct snmp_session *);

#ifdef __cplusplus
}
#endif

#endif              /* SQUID_SNMP_CLIENT_H */

