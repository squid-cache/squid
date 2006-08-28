/*
 * $Id: ntlm.h,v 1.9 2006/08/28 09:06:41 serassio Exp $
 *
 * AUTHOR: Andrew Doran <ad@interlude.eu.org>
 *
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
 */

#ifndef _NTLM_H_
#define _NTLM_H_

/* undefine this to have strict protocol adherence. You don't really need
 * that though */
#define IGNORANCE_IS_BLISS

#include <sys/types.h>

/* All of this cruft is little endian */
#include "squid_endian.h"

/* NTLM request types that we know about */
#define NTLM_ANY          0

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
void ntlmMakeChallenge(struct ntlm_challenge *chal, int32_t flags);
int ntlmCheckHeader(ntlmhdr * hdr, int type);
int ntlmCheckNegotiation(struct ntlm_negotiate *neg);
int ntlmAuthenticate(struct ntlm_authenticate *neg);

#define safe_free(x)	if (x) { free(x); x = NULL; }

#undef debug

/************* CONFIGURATION ***************/
/*
 * define this if you want debugging
 */
#ifndef DEBUG
#define DEBUG
#endif

#define FAIL_DEBUG 0

/************* END CONFIGURATION ***************/

#include <sys/types.h>

extern int debug_enabled;
#if FAIL_DEBUG
extern int fail_debug_enabled;
#endif

/* Debugging stuff */

#ifdef __GNUC__			/* this is really a gcc-ism */
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
static const char *__foo;
#define debug(X...) if (debug_enabled) { \
                    fprintf(stderr,"ntlm-auth[%ld](%s:%d): ", (long)getpid(), \
                    ((__foo=strrchr(__FILE__,'/'))==NULL?__FILE__:__foo+1),\
                    __LINE__);\
                    fprintf(stderr,X); }
#else /* DEBUG */
#define debug(X...)		/* */
#endif /* DEBUG */
#else /* __GNUC__ */
static void
debug(char *format,...)
{
#ifdef DEBUG
#ifdef _SQUID_MSWIN_
#if FAIL_DEBUG
    if (debug_enabled || fail_debug_enabled) {
#else
    if (debug_enabled) {
#endif
	va_list args;

	va_start(args, format);
	fprintf(stderr, "ntlm-auth[%ld]: ", (long)getpid());
	vfprintf(stderr, format, args);
	va_end(args);
#if FAIL_DEBUG
	fail_debug_enabled = 0;
#endif
    }
#endif /* _SQUID_MSWIN_ */
#endif /* DEBUG */
}
#endif /* __GNUC__ */


/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2(X,Y) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#endif

#endif /* _NTLM_H_ */
