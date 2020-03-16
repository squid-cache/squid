/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * negotiate_sspi_auth: helper for Negotiate Authentication for Squid Cache
 *
 * (C)2005 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * Based on previous work of Francesco Chemolli and Robert Collins.
 *
 * Dependencies: Windows 2000 and later.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * History:
 *
 * Version 1.0
 * 29-10-2005 Guido Serassio
 *              First release.
 */

#include "squid.h"
#include "base64.h"
#include "helper/protocol_defines.h"
#include "ntlmauth/ntlmauth.h"
#include "ntlmauth/support_bits.cci"
#include "sspwin32.h"
#include "util.h"

#include <windows.h>
#include <sspi.h>
#include <security.h>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

int Negotiate_packet_debug_enabled = 0;
static int have_serverblob;

/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#define SEND3(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2(X,Y) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#define SEND3(X,Y,Z) debug("sending '" X "' to squid\n",Y,Z); printf(X "\n",Y,Z);
#endif

char *negotiate_check_auth(SSP_blobP auth, int auth_length);

/*
 * options:
 * -d enable debugging.
 * -v enable verbose Negotiate packet debugging.
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-h]\n"
            " -d  enable debugging.\n"
            " -v  enable verbose Negotiate packet debugging.\n"
            " -h  this message\n\n",
            my_program_name);
}

void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hdv"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'v':
            debug_enabled = 1;
            Negotiate_packet_debug_enabled = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '?':
            opt = optopt;
        /* fall thru to default */
        default:
            fprintf(stderr, "ERROR: unknown option: -%c. Exiting\n", opt);
            usage();
            had_error = 1;
        }
    }
    if (had_error)
        exit(EXIT_FAILURE);
}

static bool
token_decode(size_t *decodedLen, uint8_t decoded[], const char *buf)
{
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);
    if (!base64_decode_update(&ctx, decodedLen, decoded, strlen(buf), buf) ||
            !base64_decode_final(&ctx)) {
        SEND("BH base64 decode failed");
        fprintf(stderr, "ERROR: base64 decoding failed for: '%s'\n", buf);
        return false;
    }
    return true;
}

int
manage_request()
{
    char buf[HELPER_INPUT_BUFFER];
    uint8_t decoded[HELPER_INPUT_BUFFER];
    size_t decodedLen = 0;
    char helper_command[3];
    char *c;
    int status;
    int oversized = 0;
    char *ErrorMessage;
    static char cred[SSP_MAX_CRED_LEN + 1];
    BOOL Done = FALSE;

    do {
        if (fgets(buf, HELPER_INPUT_BUFFER, stdin))
            return 0;

        c = static_cast<char*>(memchr(buf, '\n', HELPER_INPUT_BUFFER));
        if (c) {
            if (oversized) {
                SEND("BH illegal request received");
                fprintf(stderr, "ERROR: Illegal request received: '%s'\n", buf);
                return 1;
            }
            *c = '\0';
        } else {
            fprintf(stderr, "No newline in '%s'\n", buf);
            oversized = 1;
        }
    } while (!c);

    if ((strlen(buf) > 3) && Negotiate_packet_debug_enabled) {
        if (!token_decode(&decodedLen, decoded, buf+3))
            return 1;
        strncpy(helper_command, buf, 2);
        debug("Got '%s' from Squid with data:\n", helper_command);
        hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
    } else
        debug("Got '%s' from Squid\n", buf);

    if (memcmp(buf, "YR ", 3) == 0) {   /* refresh-request */
        /* figure out what we got */
        if (!decodedLen /* already decoded */ && !token_decode(&decodedLen, decoded, buf+3))
            return 1;
        if (decodedLen < sizeof(ntlmhdr)) {     /* decoding failure, return error */
            SEND("NA * Packet format error");
            return 1;
        }
        /* Obtain server blob against SSPI */
        c = (char *) SSP_MakeNegotiateBlob(decoded, decodedLen, &Done, &status, cred);

        if (status == SSP_OK) {
            if (Done) {
                lc(cred);   /* let's lowercase them for our convenience */
                have_serverblob = 0;
                Done = FALSE;
                if (Negotiate_packet_debug_enabled) {
                    if (!token_decode(&decodedLen, decoded, c))
                        return 1;
                    debug("sending 'AF' %s to squid with data:\n", cred);
                    if (c != NULL)
                        hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
                    else
                        fprintf(stderr, "No data available.\n");
                    printf("AF %s %s\n", c, cred);
                } else
                    SEND3("AF %s %s", c, cred);
            } else {
                if (Negotiate_packet_debug_enabled) {
                    if (!token_decode(&decodedLen, decoded, c))
                        return 1;
                    debug("sending 'TT' to squid with data:\n");
                    hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
                    printf("TT %s\n", c);
                } else {
                    SEND2("TT %s", c);
                }
                have_serverblob = 1;
            }
        } else
            SEND("BH can't obtain server blob");
        return 1;
    }
    if (memcmp(buf, "KK ", 3) == 0) {   /* authenticate-request */
        if (!have_serverblob) {
            SEND("BH invalid server blob");
            return 1;
        }
        /* figure out what we got */
        if (!decodedLen /* already decoded */ && !token_decode(&decodedLen, decoded, buf+3))
            return 1;
        if (decodedLen < sizeof(ntlmhdr)) {     /* decoding failure, return error */
            SEND("NA * Packet format error");
            return 1;
        }
        /* check against SSPI */
        c = (char *) SSP_ValidateNegotiateCredentials(decoded, decodedLen, &Done, &status, cred);

        if (status == SSP_ERROR) {
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                          FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL,
                          GetLastError(),
                          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),    /* Default language */
                          (LPTSTR) & ErrorMessage,
                          0,
                          NULL);
            if (ErrorMessage[strlen(ErrorMessage) - 1] == '\n')
                ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
            if (ErrorMessage[strlen(ErrorMessage) - 1] == '\r')
                ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
            SEND2("NA * %s", ErrorMessage);
            LocalFree(ErrorMessage);
            return 1;
        }
        if (Done) {
            lc(cred);       /* let's lowercase them for our convenience */
            have_serverblob = 0;
            Done = FALSE;
            if (Negotiate_packet_debug_enabled) {
                if (!token_decode(&decodedLen, decoded, c))
                    return 1;
                debug("sending 'AF' %s to squid with data:\n", cred);
                if (c != NULL)
                    hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
                else
                    fprintf(stderr, "No data available.\n");
                printf("AF %s %s\n", c, cred);
            } else {
                SEND3("AF %s %s", c, cred);
            }
            return 1;
        } else {
            if (Negotiate_packet_debug_enabled) {
                if (!token_decode(&decodedLen, decoded, c))
                    return 1;
                debug("sending 'TT' to squid with data:\n");
                hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
                printf("TT %s\n", c);
            } else
                SEND2("TT %s", c);
            return 1;
        }

    } else {            /* not an auth-request */
        SEND("BH illegal request received");
        fprintf(stderr, "Illegal request received: '%s'\n", buf);
        return 1;
    }
    SEND("BH detected protocol error");
    return 1;
    /********* END ********/
}

int
main(int argc, char *argv[])
{
    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s " VERSION " " SQUID_BUILD_INFO " starting up...\n", my_program_name);

    if (LoadSecurityDll(SSP_NTLM, NEGOTIATE_PACKAGE_NAME) == NULL) {
        fprintf(stderr, "FATAL: %s: can't initialize SSPI, exiting.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    debug("SSPI initialized OK\n");

    atexit(UnloadSecurityDll);

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (manage_request()) {
        /* everything is done within manage_request */
    }
    return EXIT_SUCCESS;
}

