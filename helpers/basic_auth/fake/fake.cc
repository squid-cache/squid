/*
 * AUTHOR: Amos Jeffries <squid3@treenet.co.nz>
 *
 * Fake Basic Authentication program for Squid.
 *
 * This code gets the user details and returns OK.
 * It is intended for testing use and as a base for further implementation.
 *
 *
 * This code is copyright (C) 2009 by Treehouse Networks Ltd
 * of New Zealand. It is published and Licensed as an extension of
 * squid under the same conditions as the main squid application.
 */

#include "squid.h"
#include "helpers/defines.h"

#if HAVE_CSTRING
#include <cstring>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

/**
 * options:
 * -d enable debugging.
 * -h interface help.
 */
char *program_name = NULL;

static void
usage(void)
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-h]\n"
            " -d  enable debugging.\n"
            " -h  this message\n\n",
            program_name);
}

static void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hd"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            fprintf(stderr, "%s: FATAL: unknown option: -%c. Exiting\n", program_name, opt);
            usage();
            exit(1);
        }
    }
}

int
main(int argc, char *argv[])
{
    char buf[HELPER_INPUT_BUFFER];
    int buflen = 0;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    program_name = argv[0];

    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", program_name);

    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {
        char *p;

        if ((p = strchr(buf, '\n')) != NULL) {
            *p = '\0';		/* strip \n */
            buflen = p - buf;   /* length is known already */
        } else
            buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */

        debug("Got %d bytes '%s' from Squid\n", buflen, buf);

        /* send 'OK' result back to Squid */
        SEND_OK("");
    }
    debug("%s build " __DATE__ ", " __TIME__ " shutting down...\n", program_name);
    exit(0);
}
