
/* $Id: getfullhostname.c,v 1.4 1996/04/14 03:25:23 wessels Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "util.h"


/*
 *  getfullhostname() - Returns the fully qualified name of the current 
 *  host, or NULL on error.  Pointer is only valid until the next call
 *  to the gethost*() functions.
 */
char *getfullhostname()
{
    struct hostent *hp = NULL;
    static char buf[SQUIDHOSTNAMELEN + 1];
    extern int gethostname();	/* UNIX system call */

    if (gethostname(buf, SQUIDHOSTNAMELEN) < 0)
	return (NULL);
    if ((hp = gethostbyname(buf)) == NULL)
	return (buf);
    return (hp->h_name);
}
