/*
 * Adapted By Rabellino Sergio (rabellino@di.unito.it) For Solaris 2.x
 * From NCSA Authentication module
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
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "util.h"
#include "hash.h"

#include "nis_support.h"

int
main(int argc, char **argv)
{
    char buf[256];
    char *nisdomain;
    char *nismap;
    char *user, *passwd, *p;
    char *nispasswd;

    setbuf(stdout, NULL);

    if (argc != 3) {
        fprintf(stderr, "Usage: yp_auth <domainname> <nis map for password>\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example yp_auth mydomain.com passwd.byname\n");
        exit(1);
    }
    nisdomain = argv[1];
    nismap = argv[2];

    while (fgets(buf, 256, stdin) != NULL) {
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';		/* strip \n */

        if ((user = strtok(buf, " ")) == NULL) {
            printf("ERR\n");
            continue;
        }
        if ((passwd = strtok(NULL, "")) == NULL) {
            printf("ERR\n");
            continue;
        }

        rfc1738_unescape(user);
        rfc1738_unescape(passwd);

        nispasswd = get_nis_password(user, nisdomain, nismap);

        if (!nispasswd) {
            /* User does not exist */
            printf("ERR No such user\n");
        } else if (strcmp(nispasswd, (char *) crypt(passwd, nispasswd)) == 0) {
            /* All ok !, thanks... */
            printf("OK\n");
        } else {
            /* Password incorrect */
            printf("ERR Wrong password\n");
        }
    }
    exit(0);
}
