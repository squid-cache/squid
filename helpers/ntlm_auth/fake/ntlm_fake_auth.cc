/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Andrew Doran <ad@interlude.eu.org>
 * AUTHOR: Robert Collins <rbtcollins@hotmail.com>
 * AUTHOR: Guido Serassio <guido.serassio@acmeconsulting.it>
 */

/*
 * Example ntlm authentication program for Squid, based on the
 * original proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>. Initial ntlm code by
 * Andrew Doran <ad@interlude.eu.org>.
 *
 * This code gets the username and returns it. No validation is done.
 * and by the way: it is a complete patch-up. Use the "real thing" NTLMSSP
 * if you can.
 *
 * Revised by Guido Serassio: <guido.serassio@acmeconsulting.it>
 *
 * - Added negotiation of UNICODE char support
 * - More detailed debugging info
 *
 */

/* undefine this to have strict protocol adherence. You don't really need
 * that though */
#define IGNORANCE_IS_BLISS

#include "squid.h"
#include "base64.h"
#include "helpers/defines.h"
#include "ntlmauth/ntlmauth.h"
#include "ntlmauth/support_bits.cci"

#include <cctype>
#include <cstring>
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

/* A couple of harmless helper macros */
#define SEND(X) {debug("sending '%s' to squid\n",X); printf(X "\n");}
#ifdef __GNUC__
#define SEND2(X,Y...) {debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);}
#define SEND4(X,Y...) {debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);}
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2(X,Y) {debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);}
#define SEND4(X,Y,Z,W) {debug("sending '" X "' to squid\n",Y,Z,W); printf(X "\n",Y,Z,W);}
#endif

const char *authenticate_ntlm_domain = "WORKGROUP";
int strip_domain_enabled = 0;
int NTLM_packet_debug_enabled = 0;

/*
 * options:
 * -d enable debugging.
 * -v enable verbose NTLM packet debugging.
 * -l if specified, changes behavior on failures to last-ditch.
 */
char *my_program_name = NULL;

static void
usage(void)
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-h]\n"
            " -d  enable debugging.\n"
            " -S  strip domain from username.\n"
            " -v  enable verbose NTLM packet debugging.\n"
            " -h  this message\n\n",
            my_program_name);
}

static void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hdvS"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'v':
            debug_enabled = 1;
            NTLM_packet_debug_enabled = 1;
            break;
        case 'S':
            strip_domain_enabled = 1;
            break;
        case 'h':
            usage();
            exit(0);
        case '?':
            opt = optopt;
        /* fall thru to default */
        default:
            fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
            usage();
            had_error = 1;
        }
    }
    if (had_error)
        exit(1);
}

int
main(int argc, char *argv[])
{
    char buf[HELPER_INPUT_BUFFER];
    int buflen = 0;
    char decodedBuf[HELPER_INPUT_BUFFER];
    int decodedLen;
    char user[NTLM_MAX_FIELD_LENGTH], domain[NTLM_MAX_FIELD_LENGTH];
    char *p;
    ntlmhdr *packet = NULL;
    char helper_command[3];
    int len;
    char *data = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s " VERSION " " SQUID_BUILD_INFO " starting up...\n", my_program_name);

    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {
        user[0] = '\0';     /*no user code */
        domain[0] = '\0';       /*no domain code */

        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';      /* strip \n */
        buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */
        if (buflen > 3) {
            decodedLen = base64_decode(decodedBuf, sizeof(decodedBuf), buf+3);
            packet = (ntlmhdr*)decodedBuf;
        } else {
            packet = NULL;
            decodedLen = 0;
        }
        if (buflen > 3 && NTLM_packet_debug_enabled) {
            strncpy(helper_command, buf, 2);
            helper_command[2] = '\0';
            debug("Got '%s' from Squid with data:\n", helper_command);
            hex_dump((unsigned char *)decodedBuf, decodedLen);
        } else
            debug("Got '%s' from Squid\n", buf);

        if (strncmp(buf, "YR", 2) == 0) {
            char nonce[NTLM_NONCE_LEN];
            ntlm_challenge chal;
            ntlm_make_nonce(nonce);
            if (buflen > 3) {
                ntlm_negotiate *nego = (ntlm_negotiate *)packet;
                ntlm_make_challenge(&chal, authenticate_ntlm_domain, NULL, nonce, NTLM_NONCE_LEN, nego->flags);
            } else {
                ntlm_make_challenge(&chal, authenticate_ntlm_domain, NULL, nonce, NTLM_NONCE_LEN, NTLM_NEGOTIATE_ASCII);
            }
            // TODO: find out what this context means, and why only the fake auth helper contains it.
            chal.context_high = htole32(0x003a<<16);

            len = sizeof(chal) - sizeof(chal.payload) + le16toh(chal.target.maxlen);
            data = (char *) base64_encode_bin((char *) &chal, len);
            if (NTLM_packet_debug_enabled) {
                printf("TT %s\n", data);
                debug("sending 'TT' to squid with data:\n");
                hex_dump((unsigned char *)&chal, len);
            } else
                SEND2("TT %s", data);
        } else if (strncmp(buf, "KK ", 3) == 0) {
            if (!packet) {
                SEND("BH received KK with no data! user=");
            } else if (ntlm_validate_packet(packet, NTLM_AUTHENTICATE) == NTLM_ERR_NONE) {
                if (ntlm_unpack_auth((ntlm_authenticate *)packet, user, domain, decodedLen) == NTLM_ERR_NONE) {
                    lc(user);
                    if (strip_domain_enabled) {
                        SEND2("AF %s", user);
                    } else {
                        SEND4("AF %s%s%s", domain, (*domain?"\\":""), user);
                    }
                } else {
                    lc(user);
                    SEND4("NA invalid credentials, user=%s%s%s", domain, (*domain?"\\":""), user);
                }
            } else {
                SEND("BH wrong packet type! user=");
            }
        }
    }
    exit(0);
}

