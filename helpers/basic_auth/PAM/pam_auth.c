/*
 * $Id: pam_auth.c,v 1.4 2002/01/07 01:13:10 hno Exp $
 *
 * PAM authenticator module for Squid.
 * Copyright (C) 1999 Henrik Nordstrom <hno@squid-cache.org>
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
 * requires the program to be installed suid root, or PAM will not allow
 * it to authenticate other users than it runs as (this is a security
 * limitation of PAM to avoid automated probing of passwords).
 *
 * Compile this program with: gcc -o pam_auth pam_auth.c -lpam -ldl
 *
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <security/pam_appl.h>

#define BUFSIZE 8192


/* The default PAM service name */
#ifndef SQUID_PAM_SERVICE
#define SQUID_PAM_SERVICE "squid"
#endif

/* How often to reinitialize PAM, in seconds. Undefined = never, 0=always */
/* #define PAM_CONNECTION_TTL 60 */

static int reset_pam = 1;	/* Set to one if it is time to reset PAM processing */

static char *password = NULL;	/* Workaround for Solaris 2.6 brokenness */

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
    if (!appdata_ptr) {
	/* Workaround for Solaris 2.6 where the PAM library is broken
	 * and does not pass appdata_ptr to the conversation routine
	 */
	appdata_ptr = password;
    }
    if (!appdata_ptr) {
	fprintf(stderr, "ERROR: No password available to password_converstation!\n");
	return PAM_CONV_ERR;
    }
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) {
	fprintf(stderr, "ERROR: Out of memory!\n");
	return PAM_CONV_ERR;
    }
    (*resp)[0].resp = strdup((char *) appdata_ptr);
    (*resp)[0].resp_retcode = 0;

    return ((*resp)[0].resp ? PAM_SUCCESS : PAM_CONV_ERR);
}

static struct pam_conv conv =
{
    &password_conversation,
    NULL
};

void
signal_received(int sig)
{
    reset_pam = 1;
    signal(sig, signal_received);
}

int
main(int argc, char *argv[])
{
    pam_handle_t *pamh = NULL;
    int retval;
    char *user;
    /* char *password; */
    char buf[BUFSIZE];
    time_t pamh_created = 0;

    signal(SIGHUP, signal_received);

    /* make standard output line buffered */
    setvbuf(stdout, NULL, _IOLBF, 0);

    while (retval = PAM_SUCCESS, fgets(buf, BUFSIZE, stdin)) {
	user = buf;
	password = strchr(buf, '\n');
	if (!password) {
	    fprintf(stderr, "authenticator: Unexpected input '%s'\n", buf);
	    fprintf(stdout, "ERR\n");
	    continue;
	}
	*password = '\0';
	password = strchr(buf, ' ');
	if (!password) {
	    fprintf(stderr, "authenticator: Unexpected input '%s'\n", buf);
	    fprintf(stdout, "ERR\n");
	    continue;
	}
	*password++ = '\0';
	conv.appdata_ptr = (char *) password;	/* from buf above. not allocated */
#ifdef PAM_CONNECTION_TTL
	if (pamh_created + PAM_CONNECTION_TTL >= time(NULL))
	    reset_pam = 1;
#endif
	if (reset_pam && pamh) {
	    /* Close previous PAM connection */
	    retval = pam_end(pamh, retval);
	    if (retval != PAM_SUCCESS) {
		fprintf(stderr, "ERROR: failed to release PAM authenticator\n");
	    }
	    pamh = NULL;
	}
	if (!pamh) {
	    /* Initialize PAM connection */
	    retval = pam_start(SQUID_PAM_SERVICE, "squid@", &conv, &pamh);
	    if (retval != PAM_SUCCESS) {
		fprintf(stderr, "ERROR: failed to create PAM authenticator\n");
	    }
	    reset_pam = 0;
	    pamh_created = time(NULL);
	}
	if (retval == PAM_SUCCESS)
	    retval = pam_set_item(pamh, PAM_USER, user);
	if (retval == PAM_SUCCESS)
	    retval = pam_set_item(pamh, PAM_CONV, &conv);
	if (retval == PAM_SUCCESS)
	    retval = pam_authenticate(pamh, 0);
	if (retval == PAM_SUCCESS)
	    retval = pam_acct_mgmt(pamh, 0);
	if (retval == PAM_SUCCESS) {
	    fprintf(stdout, "OK\n");
	} else {
	    fprintf(stdout, "ERR\n");
	}
    }

    if (pamh) {
	retval = pam_end(pamh, retval);
	if (retval != PAM_SUCCESS) {
	    pamh = NULL;
	    fprintf(stderr, "ERROR: failed to release PAM authenticator\n");
	}
    }
    return (retval == PAM_SUCCESS ? 0 : 1);	/* indicate success */
}
