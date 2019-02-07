/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * basic_getpwnam_auth.c
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
 * 2006-07: Giancarlo Razzolini <linux-fan@onda.com.br>
 *
 * Added functionality for doing shadow authentication too,
 * using the getspnam() function on systems that support it.
 *
 */

#include "squid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"

#include <cstdlib>
#include <cstring>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

static int
passwd_auth(char *user, char *passwd)
{
    struct passwd *pwd;
    pwd = getpwnam(user);
    if (pwd == NULL) {
        return 0;       /* User does not exist */
    } else {
        char *crypted = crypt(passwd, pwd->pw_passwd);
        if (!crypted || strcmp(pwd->pw_passwd, crypted)) {
            return 2;       /* Wrong password */
        } else {
            return 1;       /* Authentication Sucessful */
        }
    }
}

#if HAVE_SHADOW_H
static int
shadow_auth(char *user, char *passwd)
{
    struct spwd *pwd;
    pwd = getspnam(user);
    if (pwd == NULL) {
        return passwd_auth(user, passwd);   /* Fall back to passwd_auth */
    } else {
        char *crypted = crypt(passwd, pwd->sp_pwdp);
        if (!crypted || strcmp(pwd->sp_pwdp, crypted)) {
            return 2;       /* Wrong password */
        } else {
            return 1;       /* Authentication Sucessful */
        }
    }
}
#endif

int
main(int, char **)
{
    int auth = 0;
    char buf[HELPER_INPUT_BUFFER];
    char *user, *passwd, *p;

    setbuf(stdout, NULL);
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {

        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';      /* strip \n */

        if ((user = strtok(buf, " ")) == NULL) {
            SEND_ERR("No Username");
            continue;
        }
        if ((passwd = strtok(NULL, "")) == NULL) {
            SEND_ERR("No Password");
            continue;
        }
        rfc1738_unescape(user);
        rfc1738_unescape(passwd);
#if HAVE_SHADOW_H
        auth = shadow_auth(user, passwd);
#else
        auth = passwd_auth(user, passwd);
#endif
        if (auth == 0) {
            SEND_ERR("No such user");
        } else {
            if (auth == 2) {
                SEND_ERR("Wrong password");
            } else {
                SEND_OK("");
            }
        }
    }
    return 0;
}

