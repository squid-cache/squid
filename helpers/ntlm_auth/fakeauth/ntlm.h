/*
 * $Id: ntlm.h,v 1.1 2001/01/07 23:36:50 hno Exp $
 *
 * AUTHOR: Andy Doran <ad@netbsd.org>
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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

#ifndef _NTLM_H_
#define _NTLM_H_

/* undefine this to have strict protocol adherence. You don't really need
 * that though */
#define IGNORANCE_IS_BLISS

#include <sys/types.h>

/* All of this cruft is little endian */
#ifdef WORDS_BIGENDIAN
#define SSWAP(x)	(bswap16((x)))
#define WSWAP(x)	(bswap32((x)))
#else
#define SSWAP(x)	(x)
#define WSWAP(x)	(x)
#endif

/* NTLM request types that we know about */
#define NTLM_NEGOTIATE		1
#define NTLM_CHALLENGE		2
#define NTLM_AUTHENTICATE	3
#define NTLM_ANY          0

/* Header proceeding each request */
typedef struct ntlmhdr {
    char signature[8];		/* NTLMSSP */
    int32_t type;		/* One of NTLM_* from above */
} ntlmhdr;

/* String header. String data resides at the end of the request */
typedef struct strhdr {
    int16_t len;		/* Length in bytes */
    int16_t maxlen;		/* Allocated space in bytes */
    int32_t offset;		/* Offset from start of request */
} strhdr;

/* Negotiation request sent by client */
struct ntlm_negotiate {
    ntlmhdr hdr;		/* NTLM header */
    int32_t flags;		/* Request flags */
    strhdr domain;		/* Domain we wish to authenticate in */
    strhdr workstation;		/* Client workstation name */
    char pad[256];		/* String data */
};

/* Challenge request sent by server. */
struct ntlm_challenge {
    ntlmhdr hdr;		/* NTLM header */
    strhdr target;		/* Authentication target (domain/server ...) */
    int32_t flags;		/* Request flags */
    u_char challenge[8];	/* Challenge string */
    int16_t unknown[8];		/* Some sort of context data */
    char pad[256];		/* String data */
};

/* Authentication request sent by client in response to challenge */
struct ntlm_authenticate {
    ntlmhdr hdr;		/* NTLM header */
    strhdr lmresponse;		/* LANMAN challenge response */
    strhdr ntresponse;		/* NT challenge response */
    strhdr domain;		/* Domain to authenticate against */
    strhdr user;		/* Username */
    strhdr workstation;		/* Workstation name */
    strhdr sessionkey;		/* Session key for server's use */
    int32_t flags;		/* Request flags */
    char pad[256 * 6];		/* String data */
};

char *ntlmGetString(ntlmhdr * hdr, strhdr * str, int flags);
void ntlmMakeChallenge(struct ntlm_challenge *chal);
int ntlmCheckHeader(struct ntlmhdr *hdr, int type);
int ntlmCheckNegotiation(struct ntlm_negotiate *neg);
int ntlmAuthenticate(struct ntlm_authenticate *neg);

#endif /* _NTLM_H_ */
