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
 * Warning! We MIGHT be open to buffer overflows caused by malformed headers
 *
 * DONE list:
 * use hashtable to cache authentications. Yummy performance-boost, security
 *  loss should be negligible for two reasons:
 *   - if they-re using NT, there's no security to speak of anyways
 *   - it can't get worse than basic authentication.
 * cache expiration
 * challenge hash expiry and renewal.
 * PDC disconnect, after X minutes of inactivity
 *
 * TODO list:
 * change syntax from options-driven to args-driven, with args domain
 *   or domain[/\]server, and an arbitrary number of backup Domain Controllers
 * we don't really need the "status" management, it's more for debugging
 *  purposes. Remove it.
 * Maybe we can cache the created challenge, saving more time?
 *
 */


#include "config.h"
#include "ntlmauth.h"
#include "ntlm.h"
#include "util.h"

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

char load_balance = 0, failover_enabled = 0, protocol_pedantic = 0;

dc *controllers = NULL;
int numcontrollers = 0;
dc *current_dc;

/* housekeeping cycle and periodic operations */
static unsigned char need_dc_resurrection = 0;
static void
resurrect_dead_dc()
{
    int j;
    dc *c = controllers;

    need_dc_resurrection = 0;
    for (j = 0; j < numcontrollers; j++)
	if (c->status != DC_OK && is_dc_ok(c->domain, c->controller))
	    c->status = DC_OK;
}

/* makes a null-terminated string upper-case. Changes CONTENTS! */
static void
uc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = toupper(c);
	p++;
    }
}

/* makes a null-terminated string lower-case. Changes CONTENTS! */
static void
lc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = tolower(c);
	p++;
    }
}

/*
 * options:
 * -b try load-balancing the domain-controllers
 * -f fail-over to another DC if DC connection fails.
 * domain\controller ...
 */
void
process_options(int argc, char *argv[])
{
    int opt, j, had_error = 0;
    dc *new_dc = NULL, *last_dc = NULL;
    while (-1 != (opt = getopt(argc, argv, "bf"))) {
	switch (opt) {
	case 'b':
	    load_balance = 1;
	    break;
	case 'f':
	    failover_enabled = 1;
	    break;
	default:
	    fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
	    had_error = 1;
	}
    }
    if (had_error)
	exit(1);
    /* Okay, now begin filling controllers up */
    /* we can avoid memcpy-ing, and just reuse argv[] */
    for (j = optind; j < argc; j++) {
	char *d, *c;
	d = argv[j];
	if (NULL == (c = strchr(d, '\\')) && NULL == (c = strchr(d, '/'))) {
	    fprintf(stderr, "Couldn't grok domain-controller %s\n", d);
	    continue;
	}
	*c++ = '\0';
	new_dc = (dc *) malloc(sizeof(dc));
	if (!new_dc) {
	    fprintf(stderr, "Malloc error while parsing DC options\n");
	    continue;
	}
	/* capitalize */
	uc(c);
	uc(d);
	numcontrollers++;
	new_dc->domain = d;
	new_dc->controller = c;
	new_dc->status = DC_OK;
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
    const char *ch;
    for (j = 0; j < numcontrollers; j++) {
	if (current_dc->status == DC_OK) {
	    ch = make_challenge(current_dc->domain, current_dc->controller);
	    if (ch)
		return ch;	/* All went OK, returning */
	    /* Huston, we've got a problem. Take this DC out of the loop */
	    current_dc->status = DC_DEAD;
	    need_dc_resurrection = 1;
	}
	if (failover_enabled == 0)	/* No failover. Just return */
	    return NULL;
	/* Try with the next */
	current_dc = current_dc->next;
    }
    return NULL;
}

void
manage_request()
{
    ntlmhdr *fast_header;
    char buf[10240];
    const char *ch;
    char *ch2, *decoded, *cred;
    int plen;

    if (fgets(buf, BUFFER_SIZE, stdin) == NULL)
	exit(0);		/* BIIG buffer */
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
	switch (fast_header->type) {
	case NTLM_NEGOTIATE:
	    SEND("NA Invalid negotiation request received");
	    return;
	    /* notreached */
	case NTLM_CHALLENGE:
	    SEND("NA Got a challenge. We refuse to have our authority disputed");
	    return;
	    /* notreached */
	case NTLM_AUTHENTICATE:
	    /* check against the DC */
	    plen = strlen(buf) * 3 / 4;		/* we only need it here. Optimization */
	    cred = ntlm_check_auth((ntlm_authenticate *) decoded, plen);
	    if (cred == NULL) {
		switch (ntlm_errno) {
		case NTLM_LOGON_ERROR:
		    SEND("NA authentication failure");
		    dc_disconnect();
		    current_dc = current_dc->next;
		    return;
		case NTLM_SERVER_ERROR:
		    SEND("BH Domain Controller Error");
		    dc_disconnect();
		    current_dc = current_dc->next;
		    return;
		case NTLM_PROTOCOL_ERROR:
		    SEND("BH Domain Controller communication error");
		    dc_disconnect();
		    current_dc = current_dc->next;
		    return;
		case NTLM_NOT_CONNECTED:
		    SEND("BH Domain Controller (or network) died on us");
		    dc_disconnect();
		    current_dc = current_dc->next;
		    return;
		case NTLM_BAD_PROTOCOL:
		    SEND("BH Domain controller failure");
		    dc_disconnect();
		    current_dc = current_dc->next;
		    return;
		default:
		    SEND("BH Unhandled error while talking to Domain Controller");
		    dc_disconnect();
		    current_dc = current_dc->next;
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
	while (ch == NULL) {
	    sleep(30);
	    ch = obtain_challenge();
	}
	SEND2("TT %s", ch);
	if (need_dc_resurrection)	/* looks like a good moment... */
	    resurrect_dead_dc();
	return;
    }
    SEND("BH Helper detected protocol error");
    return;
/********* END ********/


}

int
main(int argc, char *argv[])
{

    debug("starting up...\n");

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
	debug("managing request\n");
	manage_request();
    }
    return 0;
}
