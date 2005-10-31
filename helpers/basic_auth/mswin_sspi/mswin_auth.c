/*
  NT_auth -  Version 2.0

  Returns OK for a successful authentication, or ERR upon error.

  Guido Serassio, Torino - Italy

  Uses code from -
    Antonino Iannella 2000
    Andrew Tridgell 1997
    Richard Sharpe 1996
    Bill Welliver 1999

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
*/

#include "config.h"
#include <stdio.h> 	 
#include <getopt.h> 	 
#include "util.h"

/* Check if we try to compile on a Windows Platform */
#if defined(_SQUID_CYGWIN_) || defined(_SQUID_MSWIN_)

#include "valid.h"

static char NTGroup[256];
char * NTAllowedGroup;
char * NTDisAllowedGroup;
int UseDisallowedGroup = 0;
int UseAllowedGroup = 0;
int debug_enabled = 0;

/*
 * options:
 * -A can specify a Windows Local Group name allowed to authenticate.
 * -D can specify a Windows Local Group name not allowed to authenticate.
 * -O can specify the default Domain against to authenticate.
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
	"%s usage:\n%s [-A|D UserGroup][-O DefaultDomain][-d]\n"
	"-A can specify a Windows Local Group name allowed to authenticate\n"
	"-D can specify a Windows Local Group name not allowed to authenticate\n"
	"-O can specify the default Domain against to authenticate\n"
	"-d enable debugging.\n"
	"-h this message\n\n",
	my_program_name, my_program_name);
}

void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;
    while (-1 != (opt = getopt(argc, argv, "dhA:D:O:"))) {
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
	case 'O':
	    strncpy(Default_NTDomain, optarg, DNLEN);
	    break;
	case 'd':
	    debug_enabled = 1;
	    break;
	case 'h':
	    usage(argv[0]);
	    exit(0);
	case '?':
	    opt = optopt;
	    /* fall thru to default */
	default:
	    fprintf(stderr, "Unknown option: -%c. Exiting\n", opt);
	    had_error = 1;
	}
    }
    if (had_error) {
	usage();
	exit(1);
    }
}

/* Main program for simple authentication.
   Scans and checks for Squid input, and attempts to validate the user.
*/

int
main(int argc, char **argv)

{
    char wstr[256];
    char username[256];
    char password[256];
    char *p;
    int err = 0;

    my_program_name = argv[0];
    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);

    if (LoadSecurityDll(SSP_BASIC, NTLM_PACKAGE_NAME) == NULL) {
	fprintf(stderr, "FATAL, can't initialize SSPI, exiting.\n");
	exit(1);
    }
    debug("SSPI initialized OK\n");

    atexit(UnloadSecurityDll);

        /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
	/* Read whole line from standard input. Terminate on break. */
	if (fgets(wstr, 255, stdin) == NULL)
	    break;

	if (NULL == strchr(wstr, '\n')) {
	    err = 1;
	    continue;
	}
	if (err) {
	    fprintf(stderr, "Oversized message\n");
            puts("ERR");
	    goto error;
	}
	
	if ((p = strchr(wstr, '\n')) != NULL)
	    *p = '\0';		/* strip \n */
	if ((p = strchr(wstr, '\r')) != NULL)
	    *p = '\0';		/* strip \r */
	/* Clear any current settings */
	username[0] = '\0';
	password[0] = '\0';
	sscanf(wstr, "%s %s", username, password);	/* Extract parameters */

        debug("Got %s from Squid\n", wstr);

	/* Check for invalid or blank entries */
	if ((username[0] == '\0') || (password[0] == '\0')) {
	    fprintf(stderr, "Invalid Request\n");
	    puts("ERR");
	    fflush(stdout);
	    continue;
	}
	rfc1738_unescape(username);
	rfc1738_unescape(password);

        debug("Trying to validate; %s %s\n", username, password);

	if (Valid_User(username, password, NTGroup) == NTV_NO_ERROR)
	    puts("OK");
	else
            printf("ERR %s\n", errormsg);
error:
	err = 0;
	fflush(stdout);
    }
    return 0;
}

#else  /* NON Windows Platform !!! */

#error NON WINDOWS PLATFORM

#endif
