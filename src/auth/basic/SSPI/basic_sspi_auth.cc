/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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
 * version 2 or later. See the file COPYING for licensing details
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
*/

#include "squid.h"
#include "auth/basic/SSPI/valid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"
#include "util.h"

#if GETOPT_H
#include <getopt.h>
#endif

/* Check if we try to compile on a Windows Platform */
#if !_SQUID_WINDOWS_
/* NON Windows Platform !!! */
#error NON WINDOWS PLATFORM
#endif

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
static void
usage(const char *name)
{
    fprintf(stderr, "Usage:\n%s [-A|D UserGroup][-O DefaultDomain][-d]\n"
            "-A can specify a Windows Local Group name allowed to authenticate\n"
            "-D can specify a Windows Local Group name not allowed to authenticate\n"
            "-O can specify the default Domain against to authenticate\n"
            "-d enable debugging.\n"
            "-h this message\n\n",
            name);
}

void
process_options(int argc, char *argv[])
{
    int opt;
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
            exit(EXIT_SUCCESS);
        case '?':
            opt = optopt;
            [[fallthrough]];
        default:
            fprintf(stderr, "FATAL: Unknown option: -%c\n", opt);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

/* Main program for simple authentication.
   Scans and checks for Squid input, and attempts to validate the user.
*/
int
main(int argc, char **argv)
{
    char wstr[HELPER_INPUT_BUFFER];
    char username[256];
    char password[256];
    char *p;
    int err = 0;

    process_options(argc, argv);

    if (LoadSecurityDll(SSP_BASIC, NTLM_PACKAGE_NAME) == NULL) {
        fprintf(stderr, "FATAL: can't initialize SSPI, exiting.\n");
        exit(EXIT_FAILURE);
    }
    debug("SSPI initialized OK\n");

    atexit(UnloadSecurityDll);

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (fgets(wstr, HELPER_INPUT_BUFFER, stdin) != NULL) {

        if (NULL == strchr(wstr, '\n')) {
            err = 1;
            continue;
        }
        if (err) {
            SEND_ERR("Oversized message");
            err = 0;
            fflush(stdout);
            continue;
        }

        if ((p = strchr(wstr, '\n')) != NULL)
            *p = '\0';      /* strip \n */
        if ((p = strchr(wstr, '\r')) != NULL)
            *p = '\0';      /* strip \r */
        /* Clear any current settings */
        username[0] = '\0';
        password[0] = '\0';
        sscanf(wstr, "%s %s", username, password);  /* Extract parameters */

        debug("Got %s from Squid\n", wstr);

        /* Check for invalid or blank entries */
        if ((username[0] == '\0') || (password[0] == '\0')) {
            SEND_ERR("Invalid Request");
            fflush(stdout);
            continue;
        }
        rfc1738_unescape(username);
        rfc1738_unescape(password);

        debug("Trying to validate; %s %s\n", username, password);

        if (Valid_User(username, password, NTGroup) == NTV_NO_ERROR)
            SEND_OK("");
        else
            SEND_ERR(errormsg);
        err = 0;
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}

