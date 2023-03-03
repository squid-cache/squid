/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Adapted By Rabellino Sergio (rabellino@di.unito.it) For Solaris 2.x
 * From NCSA Authentication module
 */

#include "squid.h"
#include "auth/basic/NIS/nis_support.h"
#include "hash.h"
#include "rfc1738.h"
#include "util.h"

#include <cstdlib>
#include <cstring>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

int
main(int argc, char **argv)
{
    char buf[256];
    char *nisdomain;
    char *nismap;
    char *user, *passwd, *p;
    char *nispasswd;

    setbuf(stdout, nullptr);

    if (argc != 3) {
        fprintf(stderr, "Usage: basic_nis_auth <domainname> <nis map for password>\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example basic_nis_auth mydomain.com passwd.byname\n");
        exit(EXIT_FAILURE);
    }
    nisdomain = argv[1];
    nismap = argv[2];

    while (fgets(buf, 256, stdin) != nullptr) {
        if ((p = strchr(buf, '\n')) != nullptr)
            *p = '\0';      /* strip \n */

        if ((user = strtok(buf, " ")) == nullptr) {
            printf("ERR\n");
            continue;
        }
        if ((passwd = strtok(nullptr, "")) == nullptr) {
            printf("ERR\n");
            continue;
        }

        rfc1738_unescape(user);
        rfc1738_unescape(passwd);

        nispasswd = get_nis_password(user, nisdomain, nismap);

        if (!nispasswd) {
            /* User does not exist */
            printf("ERR No such user\n");
            continue;
        }

#if HAVE_CRYPT
        char *crypted = nullptr;
        if ((crypted = crypt(passwd, nispasswd)) && strcmp(nispasswd, crypted) == 0) {
            /* All ok !, thanks... */
            printf("OK\n");
        } else {
            /* Password incorrect */
            printf("ERR Wrong password\n");
        }
#else
        /* Password incorrect */
        printf("BH message=\"Missing crypto capability\"\n");
#endif
    }
    return EXIT_SUCCESS;
}

