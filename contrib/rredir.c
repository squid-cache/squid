/* $Id$

/*
 * From:    richard@hekkihek.hacom.nl (Richard Huveneers)
 * To:      squid-users@nlanr.net
 * Subject: Save 15% on your bandwidth...
 * Date:    12 Sep 1996 21:21:55 GMT
 * ===========================================================================
 *
 * I have downloaded the multi-megabyte files from Netscape and Microsoft
 * that our users like to download from every mirror in the world,
 * defeating the usual caching.
 *
 * I put these files in a separate directory and installed a basic
 * redirector for Squid that checks if the file (so hostname and pathname
 * are disregarded) is present in this directory.
 *
 * After a few days of testing (the redirector looks very stable) it looks
 * like this is saving us approx. 15% on our cache flow. Also, our own WWW
 * server has become more popular than ever :)
 *
 * I'm sure this code will be useful to others too, so I've attached it at
 * the end of this message. Improvements, extensions etc. are welcome.
 *
 * I'm going on holidays now, so I won't be able to respond to e-mail
 * quickly.
 *
 * Enjoy, Richard.
 */

/*
 * rredir - redirect to local directory
 *
 * version 0.1, 7 sep 1996
 * - initial version (Richard Huveneers <Richard.Huveneers@hekkihek.hacom.nl>)
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define ACCESS_LOCAL_DIR        "/var/lib/httpd/htdocs/local/rredir"
#define REDIRECT_TO_URL         "http://www.hacom.nl/local/rredir"
#define BUFFER_SIZE             (16*1024)

int
main()
{
    char buf[BUFFER_SIZE];
    char *s, *t;
    int tlu = 0;

    /* make standard output line buffered */
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
        return 1;

    /* speed up the access() calls below */
    if (chdir(ACCESS_LOCAL_DIR) == -1)
        return 1;

    /* scan standard input */
    while (fgets(buf, BUFFER_SIZE, stdin) != NULL) {
        /* check for too long urls */
        if (strchr(buf, '\n') == NULL) {
            tlu = 1;
            continue;
        }
        if (tlu)
            goto dont_redirect;

        /* determine end of url */
        if ((s = strchr(buf, ' ')) == NULL)
            goto dont_redirect;
        *s = '\0';

        /* determine first character of filename */
        if ((s = strrchr(buf, '/')) == NULL)
            goto dont_redirect;
        s++;

        /* security: do not redirect to hidden files, the current
         * directory or the parent directory */
        if (*s == '.' || *s == '\0')
            goto dont_redirect;

        /* map filename to lower case */
        for (t = s; *t != '\0'; t++)
            *t = (char) tolower((int) *t);

        /* check for a local copy of this file */
        if (access(s, R_OK) == 0) {
            (void) printf("%s/%s\n", REDIRECT_TO_URL, s);
            continue;
        }
dont_redirect:
        tlu = 0;
        (void) printf("\n");
    }

    return 0;
}
