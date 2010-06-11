/*
 * $Id$
 *
 * AUTHOR: Andrew Doran <ad@interlude.eu.org>
 * AUTHOR: Robert Collins <rbtcollins@hotmail.com>
 * AUTHOR: Guido Serassio: <guido.serassio@acmeconsulting.it>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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

#include "config.h"
#include "ntlmauth.h"
#include "util.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif


#define safe_free(x)	if (x) { free(x); x = NULL; }

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

#define ERR    "ERR\n"
#define OK     "OK\n"

#define BUFFER_SIZE 10240

const char *authenticate_ntlm_domain = "WORKGROUP";
int strip_domain_enabled = 0;
int NTLM_packet_debug_enabled = 0;

static void
hex_dump(unsigned char *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    if (!data)
        return;

    if (debug_enabled) {
        unsigned char *p = data;
        unsigned char c;
        int n;
        char bytestr[4] = {0};
        char addrstr[10] = {0};
        char hexstr[16 * 3 + 5] = {0};
        char charstr[16 * 1 + 5] = {0};
        for (n = 1; n <= size; n++) {
            if (n % 16 == 1) {
                /* store address for this line */
                snprintf(addrstr, sizeof(addrstr), "%.4x",
                         (int) (p - data));
            }
            c = *p;
            if (xisalnum(c) == 0) {
                c = '.';
            }
            /* store hex str (for left side) */
            snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
            strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

            /* store char str (for right side) */
            snprintf(bytestr, sizeof(bytestr), "%c", c);
            strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

            if (n % 16 == 0) {
                /* line completed */
                fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
                hexstr[0] = 0;
                charstr[0] = 0;
            } else if (n % 8 == 0) {
                /* half line: add whitespaces */
                strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
                strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
            }
            p++;		/* next byte */
        }

        if (strlen(hexstr) > 0) {
            /* print rest of buffer if not empty */
            fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
        }
    }
}


/* makes a null-terminated string lower-case. Changes CONTENTS! */
static void
lc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
        *p = xtolower(c);
        p++;
    }
}

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
    char buf[BUFFER_SIZE];
    int buflen = 0;
    char user[NTLM_MAX_FIELD_LENGTH], domain[NTLM_MAX_FIELD_LENGTH];
    char *p, *decoded = NULL;
    ntlmhdr *packet = NULL;
    char helper_command[3];
    int len;
    char *data = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);

    while (fgets(buf, BUFFER_SIZE, stdin) != NULL) {
        user[0] = '\0';		/*no user code */
        domain[0] = '\0';		/*no domain code */

        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';		/* strip \n */
        buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */
        if (buflen > 3)
            packet = (ntlmhdr*)base64_decode(buf + 3);
        if (buflen > 3 && NTLM_packet_debug_enabled) {
            strncpy(helper_command, buf, 2);
            helper_command[2] = '\0';
            debug("Got '%s' from Squid with data:\n", helper_command);
            hex_dump((unsigned char*)packet, ((buflen - 3) * 3) / 4);
        } else
            debug("Got '%s' from Squid\n", buf);

        if (strncasecmp(buf, "YR", 2) == 0) {
            char nonce[NTLM_NONCE_LEN];
            ntlm_challenge chal;
            ntlm_make_nonce(nonce);
            if (buflen > 3) {
                ntlm_negotiate *nego = (ntlm_negotiate *)packet;
                ntlm_make_challenge(&chal, authenticate_ntlm_domain, NULL, nonce, NTLM_NONCE_LEN, nego->flags);
            } else {
                ntlm_make_challenge(&chal, authenticate_ntlm_domain, NULL, nonce, NTLM_NONCE_LEN, NEGOTIATE_ASCII);
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
        } else if (strncasecmp(buf, "KK ", 3) == 0) {
            if (!packet) {
                SEND("BH received KK with no data! user=");
            } else if (!ntlm_validate_packet(packet, NTLM_AUTHENTICATE)) {
                if (ntlm_unpack_auth((ntlm_authenticate *)packet, user, domain, (buflen-3)) == 0) {
                    lc(user);
                    lc(domain);
                    if (strip_domain_enabled) {
                        SEND2("AF %s", user);
                    } else {
                        SEND3("AF %s%s%s", domain, (*domain?"\\":""), user);
                    }
                } else {
                    lc(user);
                    lc(domain);
                    SEND3("NA invalid credentials, user=%s%s%s", domain, (*domain?"\\":""), user);
                }
            } else {
                SEND("BH wrong packet type! user=");
            }
        }
    }
    exit(0);
}
