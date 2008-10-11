/*
 * mswin_negotiate_auth: helper for Negotiate Authentication for Squid Cache
 *
 * (C)2005 Guido Serassio - Acme Consulting S.r.l.
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
 * Dependencies: Windows 2000 and later.
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
 * Version 1.0
 * 29-10-2005 Guido Serassio
 *              First release.
 *
 *
 */

#include "util.h"
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "negotiate.h"
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#define BUFFER_SIZE 10240

int debug_enabled = 0;
int Negotiate_packet_debug_enabled = 0;

static int have_serverblob;

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
  -v enable verbose Negotiate packet debugging.
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-h]\n"
            " -d  enable debugging.\n"
            " -v  enable verbose Negotiate packet debugging.\n"
            " -h  this message\n\n",
            my_program_name);
}


void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr =0;
    while (-1 != (opt = getopt(argc, argv, "hdv"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'v':
            debug_enabled = 1;
            Negotiate_packet_debug_enabled = 1;
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

int
manage_request()
{
    char buf[BUFFER_SIZE];
    char helper_command[3];
    char *c, *decoded;
    int plen, status;
    int oversized = 0;
    char * ErrorMessage;
    static char cred[SSP_MAX_CRED_LEN+1];
    BOOL Done = FALSE;

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

    if ((strlen(buf) > 3) && Negotiate_packet_debug_enabled) {
        decoded = base64_decode(buf + 3);
        strncpy(helper_command, buf, 2);
        debug("Got '%s' from Squid with data:\n", helper_command);
        hex_dump(decoded, ((strlen(buf) - 3) * 3) / 4);
    } else
        debug("Got '%s' from Squid\n", buf);

    if (memcmp(buf, "YR ", 3) == 0) {	/* refresh-request */
        /* figure out what we got */
        decoded = base64_decode(buf + 3);
        /*  Note: we don't need to manage memory at this point, since
         *  base64_decode returns a pointer to static storage.
         */
        if (!decoded) {		/* decoding failure, return error */
            SEND("NA * Packet format error, couldn't base64-decode");
            return 1;
        }
        /* Obtain server blob against SSPI */
        plen = (strlen(buf) - 3) * 3 / 4;		/* we only need it here. Optimization */
        c = (char *) SSP_MakeNegotiateBlob(decoded, plen, &Done, &status, cred);

        if (status == SSP_OK) {
            if (Done) {
                lc(cred);		/* let's lowercase them for our convenience */
                have_serverblob = 0;
                Done = FALSE;
                if (Negotiate_packet_debug_enabled) {
                    printf("AF %s %s\n",c,cred);
                    decoded = base64_decode(c);
                    debug("sending 'AF' %s to squid with data:\n", cred);
                    hex_dump(decoded, (strlen(c) * 3) / 4);
                } else
                    SEND3("AF %s %s", c, cred);
            } else {
                if (Negotiate_packet_debug_enabled) {
                    printf("TT %s\n",c);
                    decoded = base64_decode(c);
                    debug("sending 'TT' to squid with data:\n");
                    hex_dump(decoded, (strlen(c) * 3) / 4);
                } else {
                    SEND2("TT %s", c);
                }
                have_serverblob = 1;
            }
        } else
            helperfail("can't obtain server blob");
        return 1;
    }

    if (memcmp(buf, "KK ", 3) == 0) {	/* authenticate-request */
        if (!have_serverblob) {
            helperfail("invalid server blob");
            return 1;
        }
        /* figure out what we got */
        decoded = base64_decode(buf + 3);
        /*  Note: we don't need to manage memory at this point, since
         *  base64_decode returns a pointer to static storage.
         */
        if (!decoded) {		/* decoding failure, return error */
            SEND("NA * Packet format error, couldn't base64-decode");
            return 1;
        }

        /* check against SSPI */
        plen = (strlen(buf) - 3) * 3 / 4;		/* we only need it here. Optimization */
        c = (char *) SSP_ValidateNegotiateCredentials(decoded, plen, &Done, &status, cred);

        if (status == SSP_ERROR) {
#if FAIL_DEBUG
            fail_debug_enabled = 1;
#endif
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                          FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL,
                          GetLastError(),
                          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),   /* Default language */
                          (LPTSTR) &ErrorMessage,
                          0,
                          NULL);
            if (ErrorMessage[strlen(ErrorMessage) - 1] == '\n')
                ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
            if (ErrorMessage[strlen(ErrorMessage) - 1] == '\r')
                ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
            SEND2("NA * %s", ErrorMessage);
            LocalFree(ErrorMessage);
            return 1;
        }

        if (Done) {
            lc(cred);		/* let's lowercase them for our convenience */
            have_serverblob = 0;
            Done = FALSE;
            if (Negotiate_packet_debug_enabled) {
                printf("AF %s %s\n",c,cred);
                decoded = base64_decode(c);
                debug("sending 'AF' %s to squid with data:\n", cred);
                hex_dump(decoded, (strlen(c) * 3) / 4);
            } else {
                SEND3("AF %s %s", c, cred);
            }
            return 1;
        } else {
            if (Negotiate_packet_debug_enabled) {
                printf("TT %s\n",c);
                decoded = base64_decode(c);
                debug("sending 'TT' to squid with data:\n");
                hex_dump(decoded, (strlen(c) * 3) / 4);
            } else
                SEND2("TT %s", c);
            return 1;
        }

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

    if (LoadSecurityDll(SSP_NTLM, NEGOTIATE_PACKAGE_NAME) == NULL) {
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
