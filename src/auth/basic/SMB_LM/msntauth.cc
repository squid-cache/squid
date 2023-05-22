/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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

#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <syslog.h>

#include "auth/basic/SMB_LM/msntauth.h"
#include "auth/basic/SMB_LM/valid.h"

static char msntauth_version[] = "Msntauth v3.0.0 (C) 2 Sep 2001 Stellar-X Antonino Iannella.\nModified by the Squid HTTP Proxy team 2002-2014";

struct domaincontroller {
    std::string domain;
    std::string server;
};
typedef std::vector<domaincontroller> domaincontrollers_t;
domaincontrollers_t domaincontrollers;

bool
validate_user(char *username, char *password)
{
    for (domaincontrollers_t::iterator dc = domaincontrollers.begin(); dc != domaincontrollers.end(); ++dc) {
        //std::cerr << "testing against " << dc->server << std::endl;
        const int rv = Valid_User(username, password, dc->server.c_str(), NULL, dc->domain.c_str());
        //std::cerr << "check result: " << rv << std::endl;
        if (rv == NTV_NO_ERROR)
            return true;
    }
    return false;
}

static char instructions[] = "Usage instructions: basic_nsnt_auth <domainname>/<domaincontroller> [<domainname>/<domaincontroller> ...]";
void
display_usage_instructions()
{
    using std::endl;
    std::cerr << msntauth_version << endl << instructions << endl << endl;
}

// arguments: domain/server_name [domain/server_name ...]
int
main(int argc, char **argv)
{
    char username[256];
    char password[256];
    char wstr[256];
    int err = 0;

    openlog("basic_smb_lm_auth", LOG_PID, LOG_USER);
    setbuf(stdout, NULL);

    for (int j = 1; j < argc; ++j) {
        std::string arg = argv[j];
        size_t pos=arg.find('/');
        if (arg.find('/',pos+1) != std::string::npos) {
            std::cerr << "Error: can't understand domain controller specification '"
                      << arg << "'. Ignoring" << std::endl;
        }
        domaincontroller dc;
        dc.domain = arg.substr(0,pos);
        dc.server = arg.substr(pos+1);
        if (dc.domain.length() == 0 || dc.server.length() == 0) {
            std::cerr << "Error: invalid domain specification in '" << arg <<
                      "'. Ignoring." << std::endl;
            exit(EXIT_FAILURE);
        }
        domaincontrollers.push_back(dc);
    }
    if (domaincontrollers.empty()) {
        display_usage_instructions();
        std::cerr << "Error: no domain controllers specified" << std::endl;
        exit(EXIT_FAILURE);
    }

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

        rfc1738_unescape(username);
        rfc1738_unescape(password);

        if (validate_user(username, password)) {
            puts("OK");
        } else {
            syslog(LOG_INFO, "'%s' login failed", username);
            puts("ERR");
        }
        err = 0;
    }

    return EXIT_SUCCESS;
}

