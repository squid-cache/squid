
/*
 * MSNT - Microsoft Windows NT domain squid authenticator module
 * Version 2.0 by Stellar-X Pty Ltd, Antonino Iannella
 * Sun Sep  2 14:39:53 CST 2001
 * 
 * Modified to act as a Squid authenticator module.
 * Removed all Pike stuff.
 * Returns OK for a successful authentication, or ERR upon error.
 * 
 * Uses code from -
 * Andrew Tridgell 1997
 * Richard Sharpe 1996
 * Bill Welliver 1999
 * Duane Wessels 2000 (wessels@squid-cache.org)
 * 
 * Released under GNU Public License
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <sys/time.h>

#define  MSNTVERSION "Msntauth v2.0.3 (C) 2 Sep 2001 Stellar-X Antonino Iannella."

extern int OpenConfigFile();
extern int QueryServers(char *, char *);
extern void Checktimer();
extern void Check_forchange();
extern int Read_denyusers(void);
extern int Read_allowusers(void);
extern int Check_user(char *);

/* Main program for simple authentication.
 * Reads the denied user file. Sets alarm timer.
 * Scans and checks for Squid input, and attempts to validate the user.
 */

int
main()
{
    char username[256];
    char password[256];
    char wstr[256];
    char ver[100];

    /* Hidden way to imbed the authenticator release version */
    strcpy(ver, MSNTVERSION);

    /* Read configuration file. Abort wildly if error. */
    if (OpenConfigFile() == 1)
	return 1;

    /* Read denied and allowed user files.
     * If they fails, there is a serious problem.
     * Check syslog messages. Deny all users while in this state.
     * The msntauth process should then be killed. */

    if ((Read_denyusers() == 1) || (Read_allowusers() == 1)) {
	while (1) {
	    fgets(wstr, 255, stdin);
	    puts("ERR");
	    fflush(stdout);
	}
    }
    /* Make Check_forchange() the handle for HUP signals.
     * Don't use alarms any more. I don't think it was very
     * portable between systems. */
    signal(SIGHUP, Check_forchange);

    while (1) {
	/* Read whole line from standard input. Terminate on break. */
	if (fgets(wstr, 255, stdin) == NULL)
	    break;

	/* Clear any current settings. Read new ones. Use \n as a 
	 * convenient EOL marker which is not even there. */
	username[0] = '\0';
	password[0] = '\0';
	sscanf(wstr, "%s %[^\n]", username, password);	/* Extract parameters */

	/* Check for invalid or blank entries */
	if ((username[0] == '\0') || (password[0] == '\0')) {
	    puts("ERR");
	    fflush(stdout);
	    continue;
	}
	Checktimer();		/* Check if the user lists have changed */

	/* Check if user is explicitly denied or allowed.
	 * If user passes both checks, they can be authenticated. */

	if (Check_user(username) == 1)
	    puts("ERR");
	else {
	    if (QueryServers(username, password) == 0)
		puts("OK");
	    else
		puts("ERR");
	}

	fflush(stdout);
    }

    return 0;
}
