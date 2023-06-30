/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * PAM authenticator module for Squid.
 *
 * Copyright (C) 1999,2002,2003 Henrik Nordstrom <hno@squid-cache.org>
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
 * Install instructions:
 *
 * This program authenticates users against a PAM configured authentication
 * service "squid". This allows you to authenticate Squid users to any
 * authentication source for which you have a PAM module. Commonly available
 * PAM modules includes "UNIX", RADIUS, Kerberos and SMB, but a lot of other
 * PAM modules are available from various sources.
 *
 * Example PAM configuration for standard UNIX passwd authentication:
 * /etc/pam.conf:
 *  squid auth     required /lib/security/pam_unix.so.1
 *  squid account  required /lib/security/pam_unix.so.1
 *
 * Note that some PAM modules (for example shadow password authentication)
 * requires the program to be installed suid root to gain access to the
 * user password database
 *
 * Change Log:
 *
 *   Version 2.3, 2009-11-06
 *      Converted to C++. Brought into line with Squid-3 code styles.
 *
 *   Version 2.2, 2003-11-05
 *      One shot mode is now the default mode of operation
 *      with persistent PAM connections enabled by -t option.
 *      Support for clearing the PAM_AUTHTOK attribute on
 *      persistent PAM connections.
 *
 *   Version 2.1, 2002-08-12
 *      Squid-2.5 support (URL encoded login, password strings)
 *
 *   Version 2.0, 2002-01-07
 *      One shot mode, command line options
 *  man page
 *
 *   Version 1.3, 1999-12-10
 *      Bugfix release 1.3 to work around Solaris 2.6
 *      brokenness (not sending arguments to conversation
 *      functions)
 *
 *   Version 1.2, internal release
 *
 *   Version 1.1, 1999-05-11
 *  Initial version
 */
#include "squid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"
#include "util.h"

#include <cassert>
#include <csignal>
#include <cstring>
#include <ctime>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

/* The default PAM service name */
#if !defined(DEFAULT_SQUID_PAM_SERVICE)
#define DEFAULT_SQUID_PAM_SERVICE "squid"
#endif

/* The default TTL */
#if !defined(DEFAULT_SQUID_PAM_TTL)
#define DEFAULT_SQUID_PAM_TTL 0
#endif

#if _SQUID_SOLARIS_
static char *password = nullptr;   /* Workaround for Solaris 2.6 brokenness */
#endif

extern "C" int password_conversation(int num_msg, PAM_CONV_FUNC_CONST_PARM struct pam_message **msg,
                                     struct pam_response **resp, void *appdata_ptr);

/**
 * A simple "conversation" function returning the supplied password.
 * Has a bit to much error control, but this is my first PAM application
 * so I'd rather check everything than make any mistakes. The function
 * expects a single converstation message of type PAM_PROMPT_ECHO_OFF.
 */
int
password_conversation(int num_msg, PAM_CONV_FUNC_CONST_PARM struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    if (num_msg != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF) {
        debug("ERROR: Unexpected PAM converstaion '%d/%s'\n", msg[0]->msg_style, msg[0]->msg);
        return PAM_CONV_ERR;
    }
#if _SQUID_SOLARIS_
    if (!appdata_ptr) {
        /* Workaround for Solaris 2.6 where the PAM library is broken
         * and does not pass appdata_ptr to the conversation routine
         */
        appdata_ptr = password;
    }
#endif
    if (!appdata_ptr) {
        debug("ERROR: No password available to password_converstation!\n");
        return PAM_CONV_ERR;
    }
    *resp = static_cast<struct pam_response *>(calloc(num_msg, sizeof(struct pam_response)));
    if (!*resp) {
        debug("ERROR: Out of memory!\n");
        return PAM_CONV_ERR;
    }
    (*resp)[0].resp = xstrdup((char *) appdata_ptr);
    (*resp)[0].resp_retcode = 0;

    return ((*resp)[0].resp ? PAM_SUCCESS : PAM_CONV_ERR);
}

static struct pam_conv conv = {
    &password_conversation,
    NULL
};

static void usage(char *program)
{
    fprintf(stderr, "Usage: %s [options..]\n", program);
    fprintf(stderr, " -n service_name\n");
    fprintf(stderr, "           The PAM service name (default \"%s\")\n", DEFAULT_SQUID_PAM_SERVICE);
    fprintf(stderr, " -t ttl    PAM connection ttl in seconds (default %d)\n", DEFAULT_SQUID_PAM_TTL);
    fprintf(stderr, "           during this time the same connection will be reused\n");
    fprintf(stderr, "           to authenticate all users\n");
    fprintf(stderr, " -o        Do not perform account mgmt (account expiration etc)\n");
    fprintf(stderr, " -1        Only one user authentication per PAM connection\n");
    fprintf(stderr, " -r        Detect and remove Negotiate/NTLM realm from username\n");
}

int
main(int argc, char *argv[])
{
    pam_handle_t *pamh = nullptr;
    int retval = PAM_SUCCESS;
    char *user;
    char *password_buf;
    char buf[HELPER_INPUT_BUFFER];
    time_t pamh_created = 0;
    int ttl = DEFAULT_SQUID_PAM_TTL;
    const char *service = DEFAULT_SQUID_PAM_SERVICE;
    int no_acct_mgmt = 0;
    int no_realm = 0;

    /* make standard output line buffered */
    setvbuf(stdout, nullptr, _IOLBF, 0);

    while (1) {
        int ch = getopt(argc, argv, "1n:t:or");
        switch (ch) {
        case -1:
            goto start;
        case 'n':
            service = optarg;
            break;
        case 't':
            ttl = atoi(optarg);
            break;
        case '1':
            ttl = 0;
            break;
        case 'o':
            no_acct_mgmt = 1;
            break;
        case 'r':
            no_realm = 1;
            break;
        default:
            fprintf(stderr, "FATAL: Unknown getopt value '%c'\n", ch);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
start:
    if (optind < argc) {
        fprintf(stderr, "FATAL: Unknown option '%s'\n", argv[optind]);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
        user = buf;
        password_buf = strchr(buf, '\n');
        if (!password_buf) {
            debug("ERROR: %s: Unexpected input '%s'\n", argv[0], buf);
            goto error;
        }
        *password_buf = '\0';
        password_buf = strchr(buf, ' ');
        if (!password_buf) {
            debug("ERROR: %s: Unexpected input '%s'\n", argv[0], buf);
            goto error;
        }
        *password_buf = '\0';
        ++password_buf;
        rfc1738_unescape(user);
        rfc1738_unescape(password_buf);
        conv.appdata_ptr = (char *) password_buf;   /* from buf above. not allocated */

        if (no_realm) {
            /* Remove DOMAIN\.. and ...@domain from the user name in case the user
             * thought this was an NTLM or Negotiate authentication popup box
             */
            char * user_ptr = strchr(user, '@');
            if (user_ptr) *user_ptr = 0;
            else {
                user_ptr = strchr(user, '\\');
                if (user_ptr) user = user_ptr + 1;
            }
        }

#if _SQUID_SOLARIS_
        /* Workaround for Solaris 2.6 where the PAM library is broken
         * and does not pass appdata_ptr to the conversation routine
         */
        password = password_buf;
#endif
        if (ttl == 0) {
            /* Create PAM connection */
            retval = pam_start(service, user, &conv, &pamh);
            if (retval != PAM_SUCCESS) {
                debug("ERROR: failed to create PAM authenticator\n");
                goto error;
            }
        } else if (!pamh || (time(NULL) - pamh_created) >= ttl || pamh_created > time(NULL)) {
            /* Close previous PAM connection */
            if (pamh) {
                retval = pam_end(pamh, retval);
                if (retval != PAM_SUCCESS) {
                    debug("WARNING: failed to release PAM authenticator\n");
                }
                pamh = nullptr;
            }
            /* Initialize persistent PAM connection */
            retval = pam_start(service, "squid@", &conv, &pamh);
            if (retval != PAM_SUCCESS) {
                debug("ERROR: failed to create PAM authenticator\n");
                goto error;
            }
            pamh_created = time(NULL);
        }
        /* Authentication */
        retval = PAM_SUCCESS;
        if (ttl != 0) {
            retval = pam_set_item(pamh, PAM_USER, user);
            if (retval == PAM_SUCCESS)
                retval = pam_set_item(pamh, PAM_CONV, &conv);
        }
        if (retval == PAM_SUCCESS)
            retval = pam_authenticate(pamh, 0);
        if (retval == PAM_SUCCESS && !no_acct_mgmt)
            retval = pam_acct_mgmt(pamh, 0);
        if (retval == PAM_SUCCESS) {
            SEND_OK("");
        } else {
error:
            SEND_ERR("");
        }
        /* cleanup */
        retval = PAM_SUCCESS;
#if defined(PAM_AUTHTOK)
        if (ttl != 0 && pamh) {
            retval = pam_set_item(pamh, PAM_AUTHTOK, nullptr);
        }
#endif
        if (pamh && (ttl == 0 || retval != PAM_SUCCESS)) {
            retval = pam_end(pamh, retval);
            if (retval != PAM_SUCCESS) {
                debug("WARNING: failed to release PAM authenticator\n");
            }
            pamh = nullptr;
        }
    }

    if (pamh) {
        retval = pam_end(pamh, retval);
        if (retval != PAM_SUCCESS) {
            pamh = nullptr;
            debug("ERROR: failed to release PAM authenticator\n");
        }
    }
    return EXIT_SUCCESS;
}

