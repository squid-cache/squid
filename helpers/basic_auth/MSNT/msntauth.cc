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
#include "squid.h"
#include "rfc1738.h"
#include "util.h"

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>

#include "msntauth.h"

extern char version[];
char msntauth_version[] = "Msntauth v2.0.3 (C) 2 Sep 2001 Stellar-X Antonino Iannella.\nModified by the Squid HTTP Proxy team 26 Jun 2002";

/* Main program for simple authentication.
 * Reads the denied user file. Sets alarm timer.
 * Scans and checks for Squid input, and attempts to validate the user.
 */

int
main(int argc, char **argv)
{
    char username[256];
    char password[256];
    char wstr[256];
    int err = 0;

    openlog("msnt_auth", LOG_PID, LOG_USER);
    setbuf(stdout, NULL);

    /* Read configuration file. Abort wildly if error. */
    if (OpenConfigFile() == 1)
        return 1;

    /*
     * Read denied and allowed user files.
     * If they fails, there is a serious problem.
     * Check syslog messages. Deny all users while in this state.
     * The msntauth process should then be killed.
     */
    if ((Read_denyusers() == 1) || (Read_allowusers() == 1)) {
        while (1) {
            memset(wstr, '\0', sizeof(wstr));
            if (fgets(wstr, 255, stdin) == NULL)
                break;
            puts("ERR");
        }
        return 1;
    }

    /*
     * Make Check_forchange() the handle for HUP signals.
     * Don't use alarms any more. I don't think it was very
     * portable between systems.
     * XXX this should be sigaction()
     */
    signal(SIGHUP, Check_forchange);

    while (1) {
        int n;
        /* Read whole line from standard input. Terminate on break. */
        memset(wstr, '\0', sizeof(wstr));
        if (fgets(wstr, 255, stdin) == NULL)
            break;
        /* ignore this line if we didn't get the end-of-line marker */
        if (NULL == strchr(wstr, '\n')) {
            err = 1;
            continue;
        }
        if (err) {
            syslog(LOG_WARNING, "oversized message");
            puts("ERR");
            err = 0;
            continue;
        }

        /*
         * extract username and password.
         * XXX is sscanf() safe?
         */
        username[0] = '\0';
        password[0] = '\0';
        n = sscanf(wstr, "%s %[^\n]", username, password);
        if (2 != n) {
            puts("ERR");
            continue;
        }
        /* Check for invalid or blank entries */
        if ((username[0] == '\0') || (password[0] == '\0')) {
            puts("ERR");
            continue;
        }
        Checktimer();		/* Check if the user lists have changed */

        rfc1738_unescape(username);
        rfc1738_unescape(password);

        /*
         * Check if user is explicitly denied or allowed.
         * If user passes both checks, they can be authenticated.
         */
        if (Check_user(username) == 1) {
            syslog(LOG_INFO, "'%s' denied", username);
            puts("ERR");
        } else if (QueryServers(username, password) == 0)
            puts("OK");
        else {
            syslog(LOG_INFO, "'%s' login failed", username);
            puts("ERR");
        }
        err = 0;
    }

    return 0;
}
