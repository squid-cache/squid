/*
 * mswin_ntlm_auth: helper for NTLM Authentication for Squid Cache
 *
 * (C)2002,2005 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * Based on previous work of Francesco Chemolli and Robert Collins.
 *
 * Dependencies: Windows NT4 SP4 and later.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * History:
 *
 * Version 1.22
 * 29-10-2005 Guido Serassio
 *              Updated for Negotiate auth support.
 * Version 1.21
 * 21-02-2004 Guido Serassio
 *              Removed control of use of NTLM NEGOTIATE packet from
 *              command line, now the support is automatic.
 * Version 1.20
 * 30-11-2003 Guido Serassio
 *              Added support for NTLM local calls.
 *              Added control of use of NTLM NEGOTIATE packet from
 *              command line.
 *              Updated documentation.
 * Version 1.10
 * 07-09-2003 Guido Serassio
 *              Now is true NTLM authenticator.
 *              More debug info.
 *              Updated documentation.
 * Version 1.0
 * 29-06-2002 Guido Serassio
 *              First release.
 *
 *
 */

#include "util.h"
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "ntlm.h"
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#define BUFFER_SIZE 10240

int debug_enabled = 0;
int NTLM_packet_debug_enabled = 0;

static int have_challenge;

char * NTAllowedGroup;
char * NTDisAllowedGroup;
int UseDisallowedGroup = 0;
int UseAllowedGroup = 0;
#if FAIL_DEBUG
int fail_debug_enabled = 0;
#endif

/* makes a null-terminated string upper-case. Changes CONTENTS! */
void
uc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = xtoupper(c);
	p++;
    }
}

/* makes a null-terminated string lower-case. Changes CONTENTS! */
static void
lc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = xtolower(c);
	p++;
    }
}

void
helperfail(const char *reason)
{
#if FAIL_DEBUG
    fail_debug_enabled =1;
#endif
    SEND2("BH %s", reason);
}

/*
  options:
  -d enable debugging.
  -v enable verbose NTLM packet debugging.
  -A can specify a Windows Local Group name allowed to authenticate.
  -D can specify a Windows Local Group name not allowed to authenticate.
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
	"Usage: %s [-d] [-v] [-A|D LocalUserGroup] [-h]\n"
	" -d  enable debugging.\n"
        " -v  enable verbose NTLM packet debugging.\n"
	" -A  specify a Windows Local Group name allowed to authenticate\n"
	" -D  specify a Windows Local Group name not allowed to authenticate\n"
	" -h  this message\n\n",
	my_program_name);
}


void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr =0;
    while (-1 != (opt = getopt(argc, argv, "hdvA:D:"))) {
	switch (opt) {
	case 'A':
	    safe_free(NTAllowedGroup);
	    NTAllowedGroup=xstrdup(optarg);
	    UseAllowedGroup = 1;
	    break;
	case 'D':
	    safe_free(NTDisAllowedGroup);
	    NTDisAllowedGroup=xstrdup(optarg);
	    UseDisallowedGroup = 1;
	    break;
	case 'd':
	    debug_enabled = 1;
	    break;
	case 'v':
	    debug_enabled = 1;
	    NTLM_packet_debug_enabled = 1;
	    break;
	case 'h':
	    usage();
	    exit(0);
	case '?':
	    opt = optopt;
	    /* fall thru to default */
	default:
	    fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
	    usage();
	    had_error = 1;
	}
    }
    if (had_error)
	exit(1);
}


const char *
obtain_challenge(ntlm_negotiate * nego, int nego_length)
{
    const char *ch = NULL;

    debug("attempting SSPI challenge retrieval\n");
    ch = SSP_MakeChallenge(nego, nego_length);
    if (ch) {
	debug("Got it\n");
	return ch;		/* All went OK, returning */
    }
    return NULL;
}


int
manage_request()
{
    ntlmhdr *fast_header;
    char buf[BUFFER_SIZE];
    char helper_command[3];
    char *c, *decoded, *cred;
    int plen;
    int oversized = 0;
    char * ErrorMessage;

try_again:
    if (fgets(buf, BUFFER_SIZE, stdin) == NULL) 
        return 0;

    c = memchr(buf, '\n', BUFFER_SIZE);	/* safer against overrun than strchr */
    if (c) {
	if (oversized) {
	    helperfail("illegal request received");
	    fprintf(stderr, "Illegal request received: '%s'\n", buf);
	    return 1;
	}
	*c = '\0';
    } else {
	fprintf(stderr, "No newline in '%s'\n", buf);
	oversized = 1;
	goto try_again;
    }
    if ((strlen(buf) > 3) && NTLM_packet_debug_enabled) {
        decoded = base64_decode(buf + 3);
        strncpy(helper_command, buf, 2);
        debug("Got '%s' from Squid with data:\n", helper_command);
        hex_dump(decoded, ((strlen(buf) - 3) * 3) / 4);
    } else
        debug("Got '%s' from Squid\n", buf);
    if (memcmp(buf, "YR", 2) == 0) {	/* refresh-request */
	/* figure out what we got */
        if (strlen(buf) > 3)
            decoded = base64_decode(buf + 3);
        else
            decoded = base64_decode(ntlm_make_negotiate());
	/* Note: we don't need to manage memory at this point, since
	 *  base64_decode returns a pointer to static storage.
	 */
	if (!decoded) {		/* decoding failure, return error */
	    SEND("NA Packet format error, couldn't base64-decode");
	    return 1;
	}
	/* fast-track-decode request type. */
	fast_header = (struct _ntlmhdr *) decoded;

	/* sanity-check: it IS a NTLMSSP packet, isn't it? */
	if (memcmp(fast_header->signature, "NTLMSSP", 8) != 0) {
	    SEND("NA Broken authentication packet");
	    return 1;
	}
	switch (fast_header->type) {
	case NTLM_NEGOTIATE:
	    /* Obtain challenge against SSPI */
            if (strlen(buf) > 3)
                plen = (strlen(buf) - 3) * 3 / 4;		/* we only need it here. Optimization */
            else
                plen = NEGOTIATE_LENGTH;
            if ((c = (char *) obtain_challenge((ntlm_negotiate *) decoded, plen)) != NULL )
            {
                if (NTLM_packet_debug_enabled) {
                    printf("TT %s\n",c);
                    decoded = base64_decode(c);
	            debug("sending 'TT' to squid with data:\n");
                    hex_dump(decoded, (strlen(c) * 3) / 4);
                    if (NTLM_LocalCall)
                        debug("NTLM Local Call detected\n");
                } else {
               	    SEND2("TT %s", c);
                }
                have_challenge = 1;
            } else
                helperfail("can't obtain challenge");
	    return 1;
	    /* notreached */
	case NTLM_CHALLENGE:
	    SEND
		("NA Got a challenge. We refuse to have our authority disputed");
	    return 1;
	    /* notreached */
	case NTLM_AUTHENTICATE:
	    SEND("NA Got authentication request instead of negotiate request");
	    return 1;
	    /* notreached */
	default:
	    helperfail("unknown refresh-request packet type");
	    return 1;
	}
	return 1;
    }
    if (memcmp(buf, "KK ", 3) == 0) {	/* authenticate-request */
        if (!have_challenge) {
	    helperfail("invalid challenge");
	    return 1;
        }
	/* figure out what we got */
	decoded = base64_decode(buf + 3);
	/* Note: we don't need to manage memory at this point, since
	 *  base64_decode returns a pointer to static storage.
	 */

	if (!decoded) {		/* decoding failure, return error */
	    SEND("NA Packet format error, couldn't base64-decode");
	    return 1;
	}
	/* fast-track-decode request type. */
	fast_header = (struct _ntlmhdr *) decoded;

	/* sanity-check: it IS a NTLMSSP packet, isn't it? */
	if (memcmp(fast_header->signature, "NTLMSSP", 8) != 0) {
	    SEND("NA Broken authentication packet");
	    return 1;
	}
	switch (fast_header->type) {
	case NTLM_NEGOTIATE:
	    SEND("NA Invalid negotiation request received");
	    return 1;
	    /* notreached */
	case NTLM_CHALLENGE:
	    SEND
		("NA Got a challenge. We refuse to have our authority disputed");
	    return 1;
	    /* notreached */
	case NTLM_AUTHENTICATE:
	    /* check against SSPI */
	    plen = (strlen(buf) - 3) * 3 / 4;		/* we only need it here. Optimization */
	    cred = ntlm_check_auth((ntlm_authenticate *) decoded, plen);
            have_challenge = 0;
	    if (cred == NULL) {
#if FAIL_DEBUG
                fail_debug_enabled =1;
#endif
		switch (ntlm_errno) {
		case NTLM_BAD_NTGROUP:
		    SEND("NA Incorrect Group Membership");
		    return 1;
		case NTLM_BAD_REQUEST:
		    SEND("NA Incorrect Request Format");
		    return 1;
		case NTLM_SSPI_ERROR:
                    FormatMessage( 
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                    FORMAT_MESSAGE_FROM_SYSTEM | 
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    GetLastError(),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                    (LPTSTR) &ErrorMessage,
                    0,
                    NULL);
                    if (ErrorMessage[strlen(ErrorMessage) - 1] == '\n')
                        ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
                    if (ErrorMessage[strlen(ErrorMessage) - 1] == '\r')
                        ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
		    SEND2("NA %s", ErrorMessage);
                    LocalFree(ErrorMessage);
		    return 1;
		default:
		    SEND("NA Unknown Error");
		    return 1;
		}
	    }
	    lc(cred);		/* let's lowercase them for our convenience */
	    SEND2("AF %s", cred);
	    return 1;
	default:
	    helperfail("unknown authentication packet type");
	    return 1;
	}
	return 1;
    } else {	/* not an auth-request */
	helperfail("illegal request received");
	fprintf(stderr, "Illegal request received: '%s'\n", buf);
	return 1;
    }
    helperfail("detected protocol error");
    return 1;
/********* END ********/
}

int
main(int argc, char *argv[])
{
    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);
    
    if (LoadSecurityDll(SSP_NTLM, NTLM_PACKAGE_NAME) == NULL) {
	fprintf(stderr, "FATAL, can't initialize SSPI, exiting.\n");
	exit(1);
    }
    debug("SSPI initialized OK\n");

    atexit(UnloadSecurityDll);

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (manage_request()) {
	/* everything is done within manage_request */
    }
    exit(0);
}
