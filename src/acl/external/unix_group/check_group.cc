/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * This is a helper for the external ACL interface for Squid Cache
 * Copyright (C) 2002 Rodrigo Albani de Campos (rodrigo@geekbunker.org)
 *
 * It reads STDIN looking for a username that matches a specified group
 * Returns `OK' if the user belongs to the group or `ERR' otherwise, as
 * described on http://devel.squid-cache.org/external_acl/config.html
 * To compile this program, use:
 *
 * gcc -o check_group check_group.c
 *
 * Author: Rodrigo Albani de Campos
 * E-Mail: rodrigo@geekbunker.org
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
 * Change Log:
 * 2010-02-24 hno
 * Removed group number limitation and fixed related uninitialized
 * pointer reference (Bug #2813)
 *
 * Revision 1.7  2004/08/15 00:29:33  hno
 * helper protocol changed to URL-escaped strings in Squid-3.0
 *
 * Revision 1.6  2002/08/12 15:48:32  hno
 * imported strwordtok from Squid, added man page, some minor fixes
 *
 * Revision 1.5  2002/07/27 14:26:49  rcampos
 * allow groups to be sent on stdin
 *
 * Revision 1.4  2002/04/17 01:58:48  camposr
 * minor corrections in the getopt
 *
 * Revision 1.3  2002/04/17 01:43:17  camposr
 * ready for action
 *
 * Revision 1.2  2002/04/17 01:32:16  camposr
 * all main routines ready
 *
 * Revision 1.1  2002/04/16 05:02:32  camposr
 * Initial revision
 *
 */
#include "squid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"
#include "util.h"

#include <cctype>
#include <cstring>
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif

/*
 * Verify if user's primary group matches groupname
 * Returns 0 if user is not on the group
 * Returns 1 otherwise
 */
static int
validate_user_pw(char *username, char *groupname)
{
    struct passwd *p;
    struct group *g;

    if ((p = getpwnam(username)) == nullptr) {
        /* Returns an error if user does not exist in the /etc/passwd */
        fprintf(stderr, "ERROR: User does not exist '%s'\n", username);
        return 0;
    } else {
        /* Verify if the this is the primary user group */
        if ((g = getgrgid(p->pw_gid)) != nullptr) {
            if ((strcmp(groupname, g->gr_name)) == 0)
                return 1;
        }
    }

    return 0;
}

static int
validate_user_gr(char *username, char *groupname)
{
    /*
     * Verify if the user belongs to groupname as listed in the
     * /etc/group file
     */
    struct group *g;

    if ((g = getgrnam(groupname)) == nullptr) {
        fprintf(stderr, "ERROR: Group does not exist '%s'\n", groupname);
        return 0;
    } else {
        while (*(g->gr_mem) != nullptr) {
            if (strcmp(*((g->gr_mem)++), username) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static void
usage(char *program)
{
    fprintf(stderr, "Usage: %s -g group1 [-g group2 ...] [-p] [-s]\n\n",
            program);
    fprintf(stderr, "-g group\n");
    fprintf(stderr,
            "			The group name or id that the user must belong in order to\n");
    fprintf(stderr,
            "			be allowed to authenticate.\n");
    fprintf(stderr,
            "-p			Verify primary user group as well\n");
    fprintf(stderr,
            "-s			Strip NT domain from usernames\n");
    fprintf(stderr,
            "-r			Strip Kerberos realm from usernames\n");
}

int
main(int argc, char *argv[])
{
    char *user, *suser, *p;
    char buf[HELPER_INPUT_BUFFER];
    char **grents = nullptr;
    int check_pw = 0, ch, ngroups = 0, i, j = 0, strip_dm = 0, strip_rm = 0;

    /* make standard output line buffered */
    setvbuf(stdout, nullptr, _IOLBF, 0);

    /* get user options */
    while ((ch = getopt(argc, argv, "dsrpg:")) != -1) {
        switch (ch) {
        case 'd':
            debug_enabled = 1;
            break;
        case 's':
            strip_dm = 1;
            break;
        case 'r':
            strip_rm = 1;
            break;
        case 'p':
            check_pw = 1;
            break;
        case 'g':
            grents = (char**)realloc(grents, sizeof(*grents) * (ngroups+1));
            grents[ngroups] = optarg;
            ++ngroups;
            break;
        case '?':
            if (xisprint(optopt)) {
                fprintf(stderr, "Unknown option '-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            [[fallthrough]];
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "FATAL: Unknown option '%s'\n", argv[optind]);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
        j = 0;
        if ((p = strchr(buf, '\n')) == nullptr) {
            /* too large message received.. skip and deny */
            fprintf(stderr, "ERROR: %s: Too large: %s\n", argv[0], buf);
            while (fgets(buf, sizeof(buf), stdin)) {
                fprintf(stderr, "ERROR: %s: Too large..: %s\n", argv[0], buf);
                if (strchr(buf, '\n') != nullptr)
                    break;
            }
            SEND_BH(HLP_MSG("Username Input too large."));
            continue;
        }
        *p = '\0';
        if ((p = strtok(buf, " ")) == nullptr) {
            SEND_BH(HLP_MSG("No username given."));
            continue;
        } else {
            user = p;
            rfc1738_unescape(user);
            if (strip_dm) {
                suser = strchr(user, '\\');
                if (!suser) suser = strchr(user, '/');
                if (suser && suser[1]) user = suser + 1;
            }
            if (strip_rm) {
                suser = strchr(user, '@');
                if (suser) *suser = '\0';
            }
            /* check groups supplied by Squid */
            while ((p = strtok(nullptr, " ")) != nullptr) {
                rfc1738_unescape(p);
                if (check_pw == 1)
                    j += validate_user_pw(user, p);
                j += validate_user_gr(user, p);
            }
        }

        /* check groups supplied on the command line */
        for (i = 0; i < ngroups; ++i) {
            if (check_pw == 1) {
                j += validate_user_pw(user, grents[i]);
            }
            j += validate_user_gr(user, grents[i]);
        }

        if (j > 0) {
            SEND_OK("");
        } else {
            SEND_ERR("");
        }
    }
    return EXIT_SUCCESS;
}

