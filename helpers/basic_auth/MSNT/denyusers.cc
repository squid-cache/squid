
/*
 * denyusers.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 *
 * These routines are to block users attempting to use the proxy which
 * have been explicitly denied by the system administrator.
 * Routines at the bottom also use the allowed user functions.
 */

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include "usersfile.h"
#include "msntauth.h"

static usersfile DenyUsers;
static int init = 0;

/* shared */
char Denyuserpath[MAXPATHLEN];	/* MAXPATHLEN defined in param.h */

int
Read_denyusers(void)
{
    if (!init) {
        memset(&DenyUsers, '\0', sizeof(DenyUsers));
        init = 1;
    }
    if (*Denyuserpath)
        return Read_usersfile(Denyuserpath, &DenyUsers);
    else
        return 0;
}

static void
Check_fordenychange(void)
{
    Check_forfilechange(&DenyUsers);
}


/*
 * Check to see if the username provided by Squid appears in the denied
 * user list. Returns 0 if the user was not found, and 1 if they were.
 */

static int
Check_ifuserdenied(char *ConnectingUser)
{
    /* If user string is empty, deny */
    if (ConnectingUser[0] == '\0')
        return 1;

    /* If denied user list is empty, allow */
    if (DenyUsers.Inuse == 0)
        return 0;

    return Check_userlist(&DenyUsers, ConnectingUser);
}

/*
 * Decides if a user is denied or allowed.
 * If they have been denied, or not allowed, return 1.
 * Else return 0.
 */

int
Check_user(char *ConnectingUser)
{
    if (Check_ifuserdenied(ConnectingUser) == 1)
        return 1;

    if (Check_ifuserallowed(ConnectingUser) == 0)
        return 1;

    return 0;
}

/*
 * Checks the denied and allowed user files for change.
 * This function is invoked when a SIGHUP signal is received.
 * It is also run after every 60 seconds, at the next request.
 */

void
Check_forchange(int signal)
{
    Check_fordenychange();
    Check_forallowchange();
}

/*
 * Checks the timer. If longer than 1 minute has passed since the last
 * time someone has accessed the proxy, then check for changes in the
 * denied user file. If longer than one minute hasn't passed, return.
 */

void
Checktimer()
{
    static time_t Lasttime;	/* The last time the timer was checked */
    static time_t Currenttime;	/* The current time */

    Currenttime = time(NULL);

    /* If timeout has expired, check the denied user file, else return */
    if (difftime(Currenttime, Lasttime) < 60)
        return;
    else {
        Check_forchange(-1);
        Lasttime = Currenttime;
    }
}
