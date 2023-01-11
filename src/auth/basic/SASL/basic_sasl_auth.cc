/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * SASL authenticator module for Squid.
 * Copyright (C) 2002 Ian Castle <ian.castle@coldcomfortfarm.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Install instructions:
 *
 * This program authenticates users against using cyrus-sasl
 *
 * Compile this program with: gcc -Wall -o sasl_auth sasl_auth.c -lsasl
 *             or with SASL2: gcc -Wall -o sasl_auth sasl_auth.c -lsasl2
 *
 */
#include "squid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"
#include "util.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#if HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#else
#include <sasl.h>
#endif

#define APP_NAME_SASL   "basic_sasl_auth"

int
main(int, char *argv[])
{
    char line[HELPER_INPUT_BUFFER];
    char *username, *password;
#if SASL_VERSION_MAJOR < 2
    const char *errstr;
#endif

    int rc;
    sasl_conn_t *conn = NULL;

    /* make standard output line buffered */
    setvbuf(stdout, NULL, _IOLBF, 0);

    rc = sasl_server_init( NULL, APP_NAME_SASL );

    if ( rc != SASL_OK ) {
        fprintf(stderr, "FATAL: %d %s\n", rc, sasl_errstring(rc, NULL, NULL ));
        exit(EXIT_FAILURE);
    }

#if SASL_VERSION_MAJOR < 2
    rc = sasl_server_new( APP_NAME_SASL, NULL, NULL, NULL, 0, &conn );
#else
    rc = sasl_server_new( APP_NAME_SASL, NULL, NULL, NULL, NULL, NULL, 0, &conn );
#endif

    if ( rc != SASL_OK ) {
        fprintf(stderr, "FATAL: %d %s\n", rc, sasl_errstring(rc, NULL, NULL ));
        exit(EXIT_FAILURE);
    }

    while ( fgets( line, HELPER_INPUT_BUFFER, stdin )) {
        username = &line[0];
        password = strchr( line, '\n' );
        if (!password) {
            debug("ERROR: %s: Unexpected input '%s'\n", argv[0], line);
            SEND_ERR("Unexpected Empty Input");
            continue;
        }
        *password = '\0';
        password = strchr ( line, ' ' );
        if (!password) {
            debug("ERROR: %s: Unexpected input '%s' (no password)\n", argv[0], line );
            SEND_ERR("No Password");
            continue;
        }
        *password = '\0';
        ++password;

        rfc1738_unescape(username);
        rfc1738_unescape(password);

#if SASL_VERSION_MAJOR < 2
        rc = sasl_checkpass(conn, username, strlen(username), password, strlen(password), &errstr);
#else
        rc = sasl_checkpass(conn, username, strlen(username), password, strlen(password));
#endif

        if ( rc != SASL_OK ) {
#if SASL_VERSION_MAJOR < 2
            if ( errstr ) {
                debug("errstr %s\n", errstr);
            }
            if ( rc != SASL_BADAUTH ) {
                debug("ERROR: %d %s\n", rc, sasl_errstring(rc, NULL, NULL));
                SEND_ERR(sasl_errstring(rc, NULL, NULL));
            } else
#endif
                SEND_ERR("");
        } else {
            SEND_OK("");
        }
    }

    sasl_dispose(&conn);
    sasl_done();
    return EXIT_SUCCESS;
}

