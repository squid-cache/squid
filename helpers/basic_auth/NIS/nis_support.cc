/*
 * Written By Rabellino Sergio (rabellino@di.unito.it) For Solaris 2.x
 */
#include "squid.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_RPC_RPC_H
#include <rpc/rpc.h>
#endif

#if _SQUID_FREEBSD_  && !defined(BOOL_DEFINED)
// BUG: FreeBSD rpcsvc/yp_* headers try to redefine bool unless we match their non-standard hack.
#define BOOL_DEFINED
#endif

#include <rpcsvc/ypclnt.h>

#if HAVE_RPCSVC_YP_PROT_H
#include <rpcsvc/yp_prot.h>
#endif

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
