/*
 * Written By Rabellino Sergio (rabellino@di.unito.it) For Solaris 2.x
 */

#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

#define NO_YPERR 0		/* There is no error */

int
get_nis_password(char *user, char *passwd, char *nisdomain, char *nismap)
{
    char *val = NULL;
    char *username = NULL;
    int vallen, res;

#ifdef DEBUG
    printf("Domain is set to %s\n", nisdomain);
    printf("YP Map is set to %s\n", nismap);
#endif

    /* Get NIS entry */
    res = yp_match(nisdomain, nismap, user, strlen(user), &val, &vallen);

    switch (res) {
    case NO_YPERR:
	username = strtok(val, ":");
	strcpy(passwd, strtok(NULL, ":"));
	free(val);
	break;
    case YPERR_YPBIND:
	syslog(LOG_ERR, "Squid Authentication through ypbind failure: can't communicate with ypbind");
	return 1;
    case YPERR_KEY:		/* No such key in map */
	return 1;
    default:
	return 1;
    }
    return 0;
}
