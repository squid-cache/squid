
/*
 * allowusers.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 * 
 * These routines are to allow users attempting to use the proxy which
 * have been explicitly allowed by the system administrator.
 * The code originated from denyusers.c.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include "usersfile.h"
#include "msntauth.h"

static usersfile AllowUsers;
static int init = 0;

/* shared */
char Allowuserpath[MAXPATHLEN];	/* MAXPATHLEN defined in param.h */

int
Read_allowusers(void)
{
    if (!init) {
	memset(&AllowUsers, '\0', sizeof(AllowUsers));
	init = 1;
    }
    if (*Allowuserpath)
	return Read_usersfile(Allowuserpath, &AllowUsers);
    else
	return 0;
}

int
Check_ifuserallowed(char *ConnectingUser)
{
    return Check_userlist(&AllowUsers, ConnectingUser);
}

void
Check_forallowchange(void)
{
    Check_forfilechange(&AllowUsers);
}
