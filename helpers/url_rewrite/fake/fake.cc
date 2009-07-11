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

#include "config.h"

#define BUFFER_SIZE 10240

/**
 * options:
 * -d enable debugging.
 * -h interface help.
 */
char *my_program_name = NULL;
int concurrent_detected = -1;


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

bool
detect_concurrent(const char *)
{
    // TODO: scan the char* input and see if it is 100% numeric.
    //   if so, enable concurrent support IDs.
}

int
main(int argc, char *argv[])
{
    char buf[BUFFER_SIZE];
    int buflen = 0;
    char helper_command[3];

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    my_program_name = argv[0];

    process_options(argc, argv);

    helper_debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);

    while (fgets(buf, BUFFER_SIZE, stdin) != NULL) {

        if ((p = strchr(buf, '\n')) != NULL) {
            *p = '\0';		/* strip \n */
            buflen = p - buf;   /* length is known already */
        }
        else
            buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */

/* TODO: later.
        if (concurrent_detected < 0)
            detect_concurrent(buf);
// */

        helper_debug("Got %d bytes '%s' from Squid\n", buflen, buf);

        /* send 'no-change' result back to Squid */
        fprintf(stdout,"\n");
    }
    helper_debug("%s build " __DATE__ ", " __TIME__ " shutting down...\n", my_program_name);
    exit(0);
}
