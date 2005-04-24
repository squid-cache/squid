/*
 * getpwnam_auth.c
 *
 * AUTHOR: Erik Hofman <erik.hofman@a1.nl>
 *         Robin Elfrink <robin@a1.nl>
 *
 * Example authentication program for Squid, based on the
 * original proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>.
 *
 * Uses getpwnam() routines for authentication.
 * This has the following advantages over the NCSA module:
 * 
 * - Allow authentication of all know local users
 * - Allows authentication through nsswitch.conf
 *   + can handle NIS(+) requests
 *   + can handle LDAP request
 *   + can handle PAM request
 *
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "util.h"

#define ERR    "ERR\n"
#define OK     "OK\n"

int
main()
{
    char buf[256];
    struct passwd *pwd;
    char *user, *passwd, *p;

    setbuf(stdout, NULL);
    while (fgets(buf, 256, stdin) != NULL) {

	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */

	if ((user = strtok(buf, " ")) == NULL) {
	    printf(ERR);
	    continue;
	}
	if ((passwd = strtok(NULL, "")) == NULL) {
	    printf(ERR);
	    continue;
	}
	rfc1738_unescape(user);
	rfc1738_unescape(passwd);
	pwd = getpwnam(user);
	if (pwd == NULL) {
	    printf("ERR No such user\n");
	} else {
	    if (strcmp(pwd->pw_passwd, (char *) crypt(passwd, pwd->pw_passwd))) {
		printf("ERR Wrong password\n");
	    } else {
		printf(OK);
	    }
	}
    }
    exit(0);
}
