/*
 * AUTHOR: Amos Jeffries <squid3@treenet.co.nz>
 *
 * Example url re-writer program for Squid.
 *
 * This code gets the url and returns it. No re-writing is done.
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
char *my_program_name = NULL;

static void
usage(void)
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-h]\n"
            " -d  enable debugging.\n"
            " -h  this message\n\n",
            my_program_name);
}

static void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hd"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
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

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);

    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {
        char *p;

        if ((p = strchr(buf, '\n')) != NULL) {
            *p = '\0';		/* strip \n */
            buflen = p - buf;   /* length is known already */
        } else
            buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */

        debug("Got %d bytes '%s' from Squid\n", buflen, buf);

        /* send 'no-change' result back to Squid */
        fprintf(stdout,"\n");
    }
    debug("%s build " __DATE__ ", " __TIME__ " shutting down...\n", my_program_name);
    exit(0);
}
