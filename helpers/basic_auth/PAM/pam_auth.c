/*
 * $Id$
 *
 * PAM authenticator module for Squid.
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
 *	man page
 *
 *   Version 1.3, 1999-12-10
 *   	Bugfix release 1.3 to work around Solaris 2.6
 *      brokenness (not sending arguments to conversation
 *      functions)
 *
 *   Version 1.2, internal release
 *
 *   Version 1.1, 1999-05-11
 *	Initial version
 *
 * Compile this program with: gcc -o pam_auth pam_auth.c -lpam -ldl
 */

#include "rfc1738.h"
#include "util.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>

#define BUFSIZE 8192


/* The default PAM service name */
#ifndef DEFAULT_SQUID_PAM_SERVICE
#define DEFAULT_SQUID_PAM_SERVICE "squid"
#endif

/* The default TTL */
#ifndef DEFAULT_SQUID_PAM_TTL
#define DEFAULT_SQUID_PAM_TTL 0
#endif

#if _SQUID_SOLARIS_
static char *password = NULL;	/* Workaround for Solaris 2.6 brokenness */
#endif

/*
 * A simple "conversation" function returning the supplied password.
 * Has a bit to much error control, but this is my first PAM application
 * so I'd rather check everything than make any mistakes. The function
 * expects a single converstation message of type PAM_PROMPT_ECHO_OFF.
 */
static int
password_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    if (num_msg != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF) {
        fprintf(stderr, "ERROR: Unexpected PAM converstaion '%d/%s'\n", msg[0]->msg_style, msg[0]->msg);
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
        fprintf(stderr, "ERROR: No password available to password_converstation!\n");
        return PAM_CONV_ERR;
    }
    *resp = (struct pam_response *)(calloc(num_msg, sizeof(struct pam_response)));
    if (!*resp) {
        fprintf(stderr, "ERROR: Out of memory!\n");
        return PAM_CONV_ERR;
    }
    (*resp)[0].resp = strdup((char *) appdata_ptr);
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
}

int
main(int argc, char *argv[])
{
    pam_handle_t *pamh = NULL;
    int retval = PAM_SUCCESS;
    char *user;
    char *password_buf;
    char buf[BUFSIZE];
    time_t pamh_created = 0;
    int ttl = DEFAULT_SQUID_PAM_TTL;
    const char *service = DEFAULT_SQUID_PAM_SERVICE;
    int no_acct_mgmt = 0;

    /* make standard output line buffered */
    setvbuf(stdout, NULL, _IOLBF, 0);

    while (1) {
        int ch = getopt(argc, argv, "1n:t:o");
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
        default:
            fprintf(stderr, "Unknown getopt value '%c'\n", ch);
            usage(argv[0]);
            exit(1);
        }
    }
start:
    if (optind < argc) {
        fprintf(stderr, "Unknown option '%s'\n", argv[optind]);
        usage(argv[0]);
        exit(1);
    }

    while (fgets(buf, BUFSIZE, stdin)) {
        user = buf;
        password_buf = strchr(buf, '\n');
        if (!password_buf) {
            fprintf(stderr, "authenticator: Unexpected input '%s'\n", buf);
            goto error;
        }
        *password_buf = '\0';
        password_buf = strchr(buf, ' ');
        if (!password_buf) {
            fprintf(stderr, "authenticator: Unexpected input '%s'\n", buf);
            goto error;
        }
        *password_buf++ = '\0';
        rfc1738_unescape(user);
        rfc1738_unescape(password_buf);
        conv.appdata_ptr = (char *) password_buf;	/* from buf above. not allocated */

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
                fprintf(stderr, "ERROR: failed to create PAM authenticator\n");
                goto error;
            }
        } else if (!pamh || (time(NULL) - pamh_created) >= ttl || pamh_created > time(NULL)) {
            /* Close previous PAM connection */
            if (pamh) {
                retval = pam_end(pamh, retval);
                if (retval != PAM_SUCCESS) {
                    fprintf(stderr, "WARNING: failed to release PAM authenticator\n");
                }
                pamh = NULL;
            }
            /* Initialize persistent PAM connection */
            retval = pam_start(service, "squid@", &conv, &pamh);
            if (retval != PAM_SUCCESS) {
                fprintf(stderr, "ERROR: failed to create PAM authenticator\n");
                goto error;
            }
            pamh_created = time(NULL);
        }
        /* Authentication */
        retval = PAM_SUCCESS;
        if (ttl != 0) {
            if (retval == PAM_SUCCESS)
                retval = pam_set_item(pamh, PAM_USER, user);
            if (retval == PAM_SUCCESS)
                retval = pam_set_item(pamh, PAM_CONV, &conv);
        }
        if (retval == PAM_SUCCESS)
            retval = pam_authenticate(pamh, 0);
        if (retval == PAM_SUCCESS && !no_acct_mgmt)
            retval = pam_acct_mgmt(pamh, 0);
        if (retval == PAM_SUCCESS) {
            fprintf(stdout, "OK\n");
        } else {
error:
            fprintf(stdout, "ERR\n");
        }
        /* cleanup */
        retval = PAM_SUCCESS;
#ifdef PAM_AUTHTOK
        if (ttl != 0) {
            if (retval == PAM_SUCCESS)
                retval = pam_set_item(pamh, PAM_AUTHTOK, NULL);
        }
#endif
        if (ttl == 0 || retval != PAM_SUCCESS) {
            retval = pam_end(pamh, retval);
            if (retval != PAM_SUCCESS) {
                fprintf(stderr, "WARNING: failed to release PAM authenticator\n");
            }
            pamh = NULL;
        }
    }

    if (pamh) {
        retval = pam_end(pamh, retval);
        if (retval != PAM_SUCCESS) {
            pamh = NULL;
            fprintf(stderr, "ERROR: failed to release PAM authenticator\n");
        }
    }
    return 0;
}
