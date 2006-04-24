/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>
 * Distributed freely under the terms of the GNU General Public License,
 * version 2. See the file COPYING for licensing details
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */


#include "config.h"
#include "ntlmauth.h"
#include "ntlm.h"
#include "squid_endian.h"
#include "util.h"
#include "smbval/smblib-common.h"
#include "smbval/rfcnb-error.h"

#include <signal.h>

/* these are part of rfcnb-priv.h and smblib-priv.h */
extern int SMB_Get_Error_Msg(int msg, char *msgbuf, int len);
extern int SMB_Get_Last_Error();
extern int SMB_Get_Last_SMB_Err();
extern int RFCNB_Get_Last_Error();

#include <errno.h>

#define BUFFER_SIZE 10240

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef DEBUG
char error_messages_buffer[BUFFER_SIZE];
#endif

char load_balance = 0, protocol_pedantic = 0;
#ifdef NTLM_FAIL_OPEN
char last_ditch_enabled = 0;
#endif

dc *controllers = NULL;
int numcontrollers = 0;
dc *current_dc;

char smb_error_buffer[1000];

/* signal handler to be invoked when the authentication operation
 * times out */
static char got_timeout = 0;
static void
timeout_during_auth(int signum)
{
    dc_disconnect();
}

/* makes a null-terminated string upper-case. Changes CONTENTS! */
static void
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
send_bh_or_ld(char *bhmessage, ntlm_authenticate * failedauth, int authlen)
{
#ifdef NTLM_FAIL_OPEN
    char *creds = NULL;
    if (last_ditch_enabled) {
	creds = fetch_credentials(failedauth, authlen);
	if (creds) {
	    lc(creds);
	    SEND2("LD %s", creds);
	} else {
	    SEND("NA last-ditch on, but no credentials");
	}
    } else {
#endif
	SEND2("BH %s", bhmessage);
#ifdef NTLM_FAIL_OPEN
    }
#endif
}

/*
 * options:
 * -b try load-balancing the domain-controllers
 * -f fail-over to another DC if DC connection fails.
 *    DEPRECATED and VERBOSELY IGNORED. This is on by default now.
 * -l last-ditch-mode
 * domain\controller ...
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
	"%s usage:\n%s [-b] [-f] [-d] [-l] domain\\controller [domain\\controller ...]\n"
	"-b enables load-balancing among controllers\n"
	"-f enables failover among controllers (DEPRECATED and always active)\n"
	"-l changes behavior on domain controller failyures to last-ditch.\n"
	"-d enables debugging statements if DEBUG was defined at build-time.\n\n"
	"You MUST specify at least one Domain Controller.\n"
	"You can use either \\ or / as separator between the domain name \n"
	"and the controller name\n",
	my_program_name, my_program_name);
}

char debug_enabled=0;

void
process_options(int argc, char *argv[])
{
    int opt, j, had_error = 0;
    dc *new_dc = NULL, *last_dc = NULL;
    while (-1 != (opt = getopt(argc, argv, "bfld"))) {
	switch (opt) {
	case 'b':
	    load_balance = 1;
	    break;
	case 'f':
	    fprintf(stderr,
		"WARNING. The -f flag is DEPRECATED and always active.\n");
	    break;
#ifdef NTLM_FAIL_OPEN
	case 'l':
	    last_ditch_enabled = 1;
	    break;
#endif
	case 'd':
		debug_enabled=1;
		break;
	default:
	    fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
	    usage();
	    had_error = 1;
	}
    }
    if (had_error)
	exit(1);
    /* Okay, now begin filling controllers up */
    /* we can avoid memcpy-ing, and just reuse argv[] */
    for (j = optind; j < argc; j++) {
	char *d, *c;
	/* d will not be freed in case of non-error. Since we don't reconfigure,
	 * it's going to live as long as the process anyways */
	d = malloc(strlen(argv[j]) + 1);
	strcpy(d, argv[j]);
	debug("Adding domain-controller %s\n", d);
	if (NULL == (c = strchr(d, '\\')) && NULL == (c = strchr(d, '/'))) {
	    fprintf(stderr, "Couldn't grok domain-controller %s\n", d);
	    free(d);
	    continue;
	}
	/* more than one delimiter is not allowed */
	if (NULL != strchr(c + 1, '\\') || NULL != strchr(c + 1, '/')) {
	    fprintf(stderr, "Broken domain-controller %s\n", d);
	    free(d);
	    continue;
	}
	*c++ = '\0';
	new_dc = (dc *) malloc(sizeof(dc));
	if (!new_dc) {
	    fprintf(stderr, "Malloc error while parsing DC options\n");
	    free(d);
	    continue;
	}
	/* capitalize */
	uc(c);
	uc(d);
	numcontrollers++;
	new_dc->domain = d;
	new_dc->controller = c;
	new_dc->dead = 0;
	if (controllers == NULL) {	/* first controller */
	    controllers = new_dc;
	    last_dc = new_dc;
	} else {
	    last_dc->next = new_dc;	/* can't be null */
	    last_dc = new_dc;
	}
    }
    if (numcontrollers == 0) {
	fprintf(stderr, "You must specify at least one domain-controller!\n");
	usage();
	exit(1);
    }
    last_dc->next = controllers;	/* close the queue, now it's circular */
}

/* tries connecting to the domain controllers in the "controllers" ring,
 * with failover if the adequate option is specified.
 */
const char *
obtain_challenge()
{
    int j = 0;
    const char *ch = NULL;
    for (j = 0; j < numcontrollers; j++) {
	debug("obtain_challenge: selecting %s\\%s (attempt #%d)\n",
	    current_dc->domain, current_dc->controller, j + 1);
	if (current_dc->dead != 0) {
	    if (time(NULL) - current_dc->dead >= DEAD_DC_RETRY_INTERVAL) {
		/* mark helper as retry-worthy if it's so. */
		debug("Reviving DC\n");
		current_dc->dead = 0;
	    } else {		/* skip it */
		debug("Skipping it\n");
		continue;
	    }
	}
	/* else branch. Here we KNOW that the DC is fine */
	debug("attempting challenge retrieval\n");
	ch = make_challenge(current_dc->domain, current_dc->controller);
	debug("make_challenge retuned %p\n", ch);
	if (ch) {
	    debug("Got it\n");
	    return ch;		/* All went OK, returning */
	}
	/* Huston, we've got a problem. Take this DC out of the loop */
	debug("Marking DC as DEAD\n");
	current_dc->dead = time(NULL);
	/* Try with the next */
	debug("moving on to next controller\n");
	current_dc = current_dc->next;
    }
    /* all DCs failed. */
    return NULL;
}


void
manage_request()
{
    ntlmhdr *fast_header;
    char buf[BUFFER_SIZE];
    const char *ch;
    char *ch2, *decoded, *cred;
    int plen;

    if (fgets(buf, BUFFER_SIZE, stdin) == NULL) {
	fprintf(stderr, "fgets() failed! dying..... errno=%d (%s)\n", errno,
	    strerror(errno));
	exit(1);		/* BIIG buffer */
    }
    debug("managing request\n");
    ch2 = memchr(buf, '\n', BUFFER_SIZE);	/* safer against overrun than strchr */
    if (ch2) {
	*ch2 = '\0';		/* terminate the string at newline. */
	ch = ch2;
    }
    debug("ntlm authenticator. Got '%s' from Squid\n", buf);

    if (memcmp(buf, "KK ", 3) == 0) {	/* authenticate-request */
	/* figure out what we got */
	decoded = base64_decode(buf + 3);
	/* Note: we don't need to manage memory at this point, since
	 *  base64_decode returns a pointer to static storage.
	 */

	if (!decoded) {		/* decoding failure, return error */
	    SEND("NA Packet format error, couldn't base64-decode");
	    return;
	}
	/* fast-track-decode request type. */
	fast_header = (struct _ntlmhdr *) decoded;

	/* sanity-check: it IS a NTLMSSP packet, isn't it? */
	if (memcmp(fast_header->signature, "NTLMSSP", 8) != 0) {
	    SEND("NA Broken authentication packet");
	    return;
	}
	switch le32toh(fast_header->type) {
	case NTLM_NEGOTIATE:
	    SEND("NA Invalid negotiation request received");
	    return;
	    /* notreached */
	case NTLM_CHALLENGE:
	    SEND
		("NA Got a challenge. We refuse to have our authority disputed");
	    return;
	    /* notreached */
	case NTLM_AUTHENTICATE:
	    /* check against the DC */
	    plen = strlen(buf) * 3 / 4;		/* we only need it here. Optimization */
	    signal(SIGALRM, timeout_during_auth);
	    alarm(30);
	    cred = ntlm_check_auth((ntlm_authenticate *) decoded, plen);
	    alarm(0);
	    signal(SIGALRM, SIG_DFL);
	    if (got_timeout != 0) {
		fprintf(stderr, "ntlm-auth[%ld]: Timeout during authentication.\n", (long)getpid());
		SEND("BH Timeout during authentication");
		got_timeout = 0;
		return;
	    }
	    if (cred == NULL) {
		int smblib_err, smb_errorclass, smb_errorcode, nb_error;
		if (ntlm_errno == NTLM_LOGON_ERROR) {	/* hackish */
			SEND("NA Logon Failure");
			return;
		}
		/* there was an error. We have two errno's to look at.
		 * libntlmssp's erno is insufficient, we'll have to look at
		 * the actual SMB library error codes, to acually figure
		 * out what's happening. The thing has braindamaged interfacess..*/
		smblib_err = SMB_Get_Last_Error();
		smb_errorclass = SMBlib_Error_Class(SMB_Get_Last_SMB_Err());
		smb_errorcode = SMBlib_Error_Code(SMB_Get_Last_SMB_Err());
		nb_error = RFCNB_Get_Last_Error();
		debug("No creds. SMBlib error %d, SMB error class %d, SMB error code %d, NB error %d\n",
		    smblib_err, smb_errorclass, smb_errorcode, nb_error);
		/* Should I use smblib_err? Actually it seems I can do as well
		 * without it.. */
		if (nb_error != 0) {	/* netbios-level error */
		    send_bh_or_ld("NetBios error!",
			(ntlm_authenticate *) decoded, plen);
		    fprintf(stderr, "NetBios error code %d (%s)\n", nb_error,
			RFCNB_Error_Strings[abs(nb_error)]);
		    return;
		}
		switch (smb_errorclass) {
		case SMBC_SUCCESS:
		    debug("Huh? Got a SMB success code but could check auth..");
		    SEND("NA Authentication failed");
		    /*
		     * send_bh_or_ld("SMB success, but no creds. Internal error?",
		     * (ntlm_authenticate *) decoded, plen);
		     */
		    return;
		case SMBC_ERRDOS:
		    /*this is the most important one for errors */
		    debug("DOS error\n");
		    switch (smb_errorcode) {
			/* two categories matter to us: those which could be
			 * server errors, and those which are auth errors */
		    case SMBD_noaccess:	/* 5 */
			SEND("NA Access denied");
			return;
		    case SMBD_badformat:
			SEND("NA bad format in authentication packet");
			return;
		    case SMBD_badaccess:
			SEND("NA Bad access request");
			return;
		    case SMBD_baddata:
			SEND("NA Bad Data");
			return;
		    default:
			send_bh_or_ld("DOS Error",
			    (ntlm_authenticate *) decoded, plen);
			return;
		    }
		case SMBC_ERRSRV:	/* server errors */
		    debug("Server error");
		    switch (smb_errorcode) {
			/* mostly same as above */
		    case SMBV_badpw:
			SEND("NA Bad password");
			return;
		    case SMBV_access:
			SEND("NA Server access error");
			return;
		    default:
			send_bh_or_ld("Server Error",
			    (ntlm_authenticate *) decoded, plen);
			return;
		    }
		case SMBC_ERRHRD:	/* hardware errors don't really matter */
		    send_bh_or_ld("Domain Controller Hardware error",
			(ntlm_authenticate *) decoded, plen);
		    return;
		case SMBC_ERRCMD:
		    send_bh_or_ld("Domain Controller Command Error",
			(ntlm_authenticate *) decoded, plen);
		    return;
		}
	    }
	    lc(cred);		/* let's lowercase them for our convenience */
	    SEND2("AF %s", cred);
	    return;
	default:
	    SEND("BH unknown authentication packet type");
	    return;
	}


	return;
    }
    if (memcmp(buf, "YR", 2) == 0) {	/* refresh-request */
	dc_disconnect();
	ch = obtain_challenge();
	/* Robert says we can afford to wait forever. I'll trust him on this
	 * one */
	while (ch == NULL) {
	    sleep(30);
	    ch = obtain_challenge();
	}
	SEND2("TT %s", ch);
	return;
    }
    SEND("BH Helper detected protocol error");
    return;
/********* END ********/


}

int
main(int argc, char *argv[])
{

    debug("ntlm_auth build " __DATE__ ", " __TIME__ " starting up...\n");
#ifdef DEBUG
    debug("changing dir to /tmp\n");
    chdir("/tmp");
#endif

    my_program_name = argv[0];
    process_options(argc, argv);

    debug("options processed OK\n");

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* select the first domain controller we're going to use */
    current_dc = controllers;
    if (load_balance != 0 && numcontrollers > 1) {
	int n;
	pid_t pid = getpid();
	n = pid % numcontrollers;
	debug("load balancing. Selected controller #%d\n", n);
	while (n > 0) {
	    current_dc = current_dc->next;
	    n--;
	}
    }
    while (1) {
	manage_request();
    }
    return 0;
}
