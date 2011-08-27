/*
 * Written By Rabellino Sergio (rabellino@di.unito.it) For Solaris 2.x
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <rpc/rpc.h>

#if _SQUID_FREEBSD_  && !defined(BOOL_DEFINED)
// BUG: FreeBSD rpcsvc/yp_* headers try to redefine bool unless we match their non-standard hack.
#define BOOL_DEFINED
#endif

#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

#include "nis_support.h"

#define NO_YPERR 0		/* There is no error */

char *
get_nis_password(char *user, char *nisdomain, char *nismap)
{
    static char *val = NULL;
    char *password = NULL;
    int vallen, res;

#ifdef DEBUG
    printf("Domain is set to %s\n", nisdomain);
    printf("YP Map is set to %s\n", nismap);
#endif

    /* Free last entry */
    if (val) {
        free(val);
        val = NULL;
    }

    /* Get NIS entry */
    res = yp_match(nisdomain, nismap, user, strlen(user), &val, &vallen);

    switch (res) {
    case NO_YPERR:
        /* username = */
        (void) strtok(val, ":");
        password = strtok(NULL, ",:");
        return password;
    case YPERR_YPBIND:
        syslog(LOG_ERR, "Squid Authentication through ypbind failure: can't communicate with ypbind");
        return NULL;
    case YPERR_KEY:		/* No such key in map */
        return NULL;
    default:
        return NULL;
    }
}
