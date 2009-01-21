/*
 * $Id$
 *
 * * * * * * * * Legal stuff * * * * * * *
 *
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>,
 *   inspired by previous work by Andrew Doran <ad@interlude.eu.org>.
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
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 * * * * * * * * Declaration of intents * * * * * * *
 *
 * This header contains definitions and defines allowing to decode and
 * understand NTLM packets, as sent by Internet Explorer.
 * It's put here as it is a common utility to all HTLM-enabled modules.
 */

#ifndef SQUID_NTLMAUTH_H
#define SQUID_NTLMAUTH_H

/* int*_t */
#include "config.h"

/* All of this cruft is little endian */
#include "squid_endian.h"

/* Used internally. Microsoft seems to think this is right, I believe them.
 * Right. */
#define MAX_FIELD_LENGTH 300	/* max length of an NTLMSSP field */


/* Here start the NTLMSSP definitions */
/* NTLM request types that we know about */
#define NTLM_NEGOTIATE		1
#define NTLM_CHALLENGE		2
#define NTLM_CHALLENGE_HEADER_OFFSET 40
#define NTLM_AUTHENTICATE	3

#define NONCE_LEN 8

/* negotiate request flags */
#define NEGOTIATE_UNICODE              0x0001
#define NEGOTIATE_ASCII                0x0002
#define NEGOTIATE_REQUEST_TARGET       0x0004
#define NEGOTIATE_REQUEST_SIGN         0x0010
#define NEGOTIATE_REQUEST_SEAL         0x0020
#define NEGOTIATE_DATAGRAM_STYLE       0x0040
#define NEGOTIATE_USE_LM               0x0080
#define NEGOTIATE_USE_NETWARE          0x0100
#define NEGOTIATE_USE_NTLM             0x0200
#define NEGOTIATE_DOMAIN_SUPPLIED      0x1000
#define NEGOTIATE_WORKSTATION_SUPPLIED 0x2000
#define NEGOTIATE_THIS_IS_LOCAL_CALL   0x4000
#define NEGOTIATE_ALWAYS_SIGN          0x8000

/* challenge request flags */
#define CHALLENGE_TARGET_IS_DOMAIN     0x10000
#define CHALLENGE_TARGET_IS_SERVER     0x20000
#define CHALLENGE_TARGET_IS_SHARE      0x40000

/* these are marked as "extra" fields */
#define REQUEST_INIT_RESPONSE          0x100000
#define REQUEST_ACCEPT_RESPONSE        0x200000
#define REQUEST_NON_NT_SESSION_KEY     0x400000


/* String header. String data resides at the end of the request */
typedef struct _strhdr {
    int16_t len;		/* Length in bytes */
    int16_t maxlen;		/* Allocated space in bytes */
    int32_t offset;		/* Offset from start of request */
} strhdr;

/* We use this to keep data/lenght couples. Only used internally. */
typedef struct _lstring {
    int32_t l;			/* length, -1 if empty */
    char *str;			/* the string. NULL if not initialized */
} lstring;

/* This is an header common to all signatures, it's used to discriminate
 * among the different signature types. */
typedef struct _ntlmhdr {
    char signature[8];		/* "NTLMSSP" */
    int32_t type;		/* One of the NTLM_* types above. */
} ntlmhdr;

/* Negotiation request sent by client */
typedef struct _ntlm_negotiate {
    char signature[8];		/* "NTLMSSP" */
    int32_t type;		/* LSWAP(0x1) */
    u_int32_t flags;		/* Request flags */
    strhdr domain;		/* Domain we wish to authenticate in */
    strhdr workstation;		/* Client workstation name */
    char payload[256];		/* String data */
} ntlm_negotiate;

/* Challenge request sent by server. */
typedef struct _ntlm_challenge {
    char signature[8];		/* "NTLMSSP" */
    int32_t type;		/* LSWAP(0x2) */
    strhdr target;		/* Authentication target (domain/server ...) */
    u_int32_t flags;		/* Request flags */
    u_char challenge[NONCE_LEN];	/* Challenge string */
    u_int32_t context_low;	/* LS part of the server context handle */
    u_int32_t context_high;	/* MS part of the server context handle */
    char payload[256];		/* String data */
} ntlm_challenge;

/* Authentication request sent by client in response to challenge */
typedef struct _ntlm_authenticate {
    char signature[8];		/* "NTLMSSP" */
    int32_t type;		/* LSWAP(0x3) */
    strhdr lmresponse;		/* LANMAN challenge response */
    strhdr ntresponse;		/* NT challenge response */
    strhdr domain;		/* Domain to authenticate against */
    strhdr user;		/* Username */
    strhdr workstation;		/* Workstation name */
    strhdr sessionkey;		/* Session key for server's use */
    int32_t flags;		/* Request flags */
    char payload[256 * 6];	/* String data */
} ntlm_authenticate;

const char *ntlm_make_challenge(char *domain, char *domain_controller,
                                char *challenge_nonce, int challenge_nonce_len);
lstring ntlm_fetch_string(char *packet, int32_t length, strhdr * str);
void ntlm_add_to_payload(char *payload, int *payload_length,
                         strhdr * hdr, char *toadd,
                         int toadd_length, int base_offset);

#endif /* SQUID_NTLMAUTH_H */
