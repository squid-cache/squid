/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>
 * (C) 2002 Andrew Bartlett <abartlet@samba.org>
 *
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
/*
 * TODO:
 * -add handling of the -d flag
 * -move all squid-helper-protocol-related operations to helper functions
 * -remove the hard-coded target NT domain name
 *
 * - MAYBE move squid-helper-protocol-related opetations to an external
 *   library?
 */


#include "wbntlm.h"
#include "util.h"
/* stdio.h is included in wbntlm.h */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>		/* for gettimeofday */
#include <errno.h>		/* BUG: is this portable? */

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "winbind_nss_config.h"
#include "winbindd_nss.h"

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

void
authfail(char *domain, char *user, char *reason)
{
    /* TODO: -move away from SEND-type gcc-isms
     *       -prepare for protocol extension as soon as rbcollins is ready
     */
    SEND2("NA %s\\%s auth failure because: %s", domain, user, reason);
}

void
authok(const char *domain, const char *user)
{
    SEND2("AF %s\\%s", domain, user);
}

void
sendchallenge(const char *challenge)
{
    SEND2("TT %s", challenge);
}

void
helperfail(const char *reason)
{
    SEND2("BH %s", reason);
}

char debug_enabled = 0;
char *myname;
pid_t mypid;

static void
lc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = tolower(c);
	p++;
    }
}

static void
uc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = toupper(c);
	p++;
    }
}



NSS_STATUS winbindd_request(int req_type,
    struct winbindd_request *request, struct winbindd_response *response);


static tristate have_urandom = DONTKNOW;
FILE *urandom_file = NULL;

void
init_random()
{
    if (have_urandom == DONTKNOW) {
	int result = 0;
	struct stat st;
	result = stat(ENTROPY_SOURCE, &st);
	if (result != 0 || !(S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))) {
	    debug("Entropy source " ENTROPY_SOURCE " is unavailable\n");
	    have_urandom = NO;
	}
	if ((urandom_file = fopen(ENTROPY_SOURCE, "r")) == NULL) {
	    unsigned int seed;
	    struct timeval t;
	    warn("Can't open entropy source " ENTROPY_SOURCE "\n");
	    have_urandom = NO;
	    gettimeofday(&t, NULL);
	    seed = squid_random() * getpid() * t.tv_sec * t.tv_usec;
	    squid_srandom(seed);
	} else {
	    have_urandom = YES;
	}
    }
}

static unsigned char challenge[CHALLENGE_LEN + 1];
static char *
build_challenge(void)
{
    size_t gotchars;
    unsigned char j;
    switch (have_urandom) {
    case YES:
	if ((gotchars = fread(&challenge, CHALLENGE_LEN, 1, urandom_file)) == 0) {
	    /* couldn't get a challenge. Fall back to random() and friends.
	     * notice that even a single changed byte is good enough for us */
	    have_urandom = NO;
	    return build_challenge();
	}
	return challenge;
    case NO:
	if (!(squid_random() % 100)) {	/* sometimes */
	    init_random();
	}
	for (j = 0; j < CHALLENGE_LEN; j++)
	    challenge[j] = (unsigned char) (squid_random() % 256);
	return challenge;
    default:
	warn("Critical internal error. Somebody forgot to initialize "
	    "the random system. Exiting.\n");
	exit(1);
    }
}

lstring lmhash, nthash;
static char have_nthash = 0;	/* simple flag. A tad dirty.. */

void
do_authenticate(ntlm_authenticate * auth, int auth_length)
{
    lstring tmp;
    int tocopy;
    NSS_STATUS winbindd_result;
    struct winbindd_request request;
    struct winbindd_response response;
    char *domain, *user;

    memset(&request, 0, sizeof(struct winbindd_request));

    memset(&response, 0, sizeof(struct winbindd_response));

    /* domain */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->domain);
    if (tmp.str == NULL || tmp.l == 0) {	/* no domain supplied */
	request.data.auth_crap.domain[0] = 0;
    } else {
	tocopy = min(tmp.l + 1, sizeof(fstring));
	xstrncpy(request.data.auth_crap.domain, tmp.str, tocopy);
    }

    domain = request.data.auth_crap.domain;	/* just a shortcut */

    /* username */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->user);
    if (tmp.str == NULL || tmp.l == 0) {
	authfail(domain, "-", "No username in request");
	return;
    }

    tocopy = min(sizeof(fstring), tmp.l + 1);
    xstrncpy(request.data.auth_crap.user, tmp.str, tocopy);
    user = request.data.auth_crap.user;

    /* now the LM hash */
    lmhash = ntlm_fetch_string((char *) auth, auth_length, &auth->lmresponse);
    switch (lmhash.l) {
    case 0:
	warn("No lm hash provided by user %s\\%s\n", domain, user);
	request.data.auth_crap.lm_resp_len = 0;
	break;
    case 24:
	memcpy(request.data.auth_crap.lm_resp, lmhash.str, 24);
	request.data.auth_crap.lm_resp_len = 24;
	break;
    default:
	authfail(domain, user, "Broken LM hash response");
	return;
    }

    nthash = ntlm_fetch_string((char *) auth, auth_length, &auth->ntresponse);
    switch (nthash.l) {
    case 0:
	debug("no nthash\n");
	request.data.auth_crap.nt_resp_len = 0;
	break;
    case 24:
	memcpy(request.data.auth_crap.nt_resp, nthash.str, 24);
	request.data.auth_crap.nt_resp_len = 24;
	break;
    default:
	debug("nthash len = %d\n", nthash.l);
	authfail(domain, user, "Broken NT hash response");
	return;
    }

    debug("Checking user '%s\\%s' lmhash len =%d, have_nthash=%d, "
	"nthash len=%d\n", domain, user, lmhash.l, have_nthash, nthash.l);

    memcpy(request.data.auth_crap.chal, challenge, CHALLENGE_LEN);

    winbindd_result = winbindd_request(WINBINDD_PAM_AUTH_CRAP,
	&request, &response);
    debug("winbindd result: %d\n", winbindd_result);

    if (winbindd_result == NSS_STATUS_SUCCESS) {
	lc(domain);
	lc(user);
	authok(domain, user);
    } else {
	char error_buf[200];
	snprintf(error_buf, sizeof(error_buf), "Authentication Failure (%s)",
	    response.data.auth.error_string);
	authfail(domain, user, error_buf);
    }
    return;			/* useless */
}

void
manage_request(char *target_domain)
{
    char buf[BUFFER_SIZE + 1];
    char *c, *decoded;
    ntlmhdr *fast_header;


    if (fgets(buf, BUFFER_SIZE, stdin) == NULL) {
	warn("fgets() failed! dying..... errno=%d (%s)\n", errno,
	    strerror(errno));
	exit(1);		/* BIIG buffer */
    }

    c = memchr(buf, '\n', BUFFER_SIZE);
    if (c)
	*c = '\0';
    else {
	warn("No newline in '%s'. Dying.\n", buf);
	exit(1);
    }

    debug("Got '%s' from squid.\n", buf);
    if (memcmp(buf, "YR", 2) == 0) {	/* refresh-request */
	sendchallenge(ntlm_make_challenge(target_domain, NULL,
		build_challenge(), CHALLENGE_LEN));
	return;
    }
    if (strncmp(buf, "KK ", 3) != 0) {	/* not an auth-request */
	helperfail("illegal request received");
	warn("Illegal request received: '%s'\n", buf);
	return;
    }
    /* At this point I'm sure it's a KK */
    decoded = base64_decode(buf + 3);
    if (!decoded) {		/* decoding failure, return error */
	authfail("-", "-", "Auth-format error, base64-decoding error");
	return;
    }
    fast_header = (struct _ntlmhdr *) decoded;

    /* sanity-check: it IS a NTLMSSP packet, isn't it? */
    if (memcmp(fast_header->signature, "NTLMSSP", 8) != 0) {
	authfail("-", "-", "Broken NTLM packet, missing NTLMSSP signature");
	return;
    }
    /* Understand what we got */
    switch (fast_header->type) {
    case NTLM_NEGOTIATE:
	authfail("-", "-", "Received neg-request while expecting auth packet");
	return;
    case NTLM_CHALLENGE:
	authfail("-", "-", "Received challenge. Refusing to abide");
	return;
    case NTLM_AUTHENTICATE:
	do_authenticate((ntlm_authenticate *) decoded,
	    (strlen(buf) - 3) * 3 / 4);
	return;
    default:
	helperfail("Unknown authentication packet type");
	return;
    }
    /* notreached */
    return;
}

static char *
get_winbind_domain(void)
{
    struct winbindd_response response;
    char *domain;

    ZERO_STRUCT(response);

    /* Send off request */

    if (winbindd_request(WINBINDD_DOMAIN_NAME, NULL, &response) !=
	NSS_STATUS_SUCCESS) {
	warn("could not obtain winbind domain name!\n");
	exit(1);
    }

    domain = strdup(response.data.domain_name);
    uc(domain);

    warn("target domain is %s\n", domain);
    return domain;
}

char *
process_options(int argc, char *argv[])
{
    int opt;
    char *target_domain = NULL;

    while (-1 != (opt = getopt(argc, argv, "d"))) {
	switch (opt) {
	case 'd':
	    debug_enabled = 1;
	    break;
	default:
	    warn("Unknown option: -%c. Exiting\n", opt);
	    exit(1);
	    break;		/* not reached */
	}
	if (optind >= argc - 1) {
	    target_domain = argv[optind];
	    warn("target domain is %s\n", target_domain);
	}
    }
    return target_domain;
}

void
check_winbindd()
{
    NSS_STATUS r;
    struct winbindd_request request;
    struct winbindd_response response;
    r = winbindd_request(WINBINDD_INTERFACE_VERSION, &request, &response);
    if (r != NSS_STATUS_SUCCESS) {
	warn("Can't contact winbindd. Dying\n");
	exit(1);
    }
    if (response.data.interface_version != WINBIND_INTERFACE_VERSION) {
	warn("Winbind protocol mismatch. Align squid and samba. Dying\n");
	exit(1);
    }
}

int
main(int argc, char **argv)
{
    char *target_domain;
    if (argc > 0) {		/* should always be true */
	myname = strrchr(argv[0], '/');
	if (myname == NULL)
	    myname = argv[0];
	else
	    myname++;
    } else {
	myname = "(unknown)";
    }
    mypid = getpid();
    target_domain = process_options(argc, argv);
    debug("ntlm winbindd auth helper build " __DATE__ ", " __TIME__
	" starting up...\n");

    check_winbindd();

    if (target_domain == NULL) {
	target_domain = get_winbind_domain();
    }

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    init_random();
    while (1) {
	manage_request(target_domain);
    }
    return 0;
}
