/* $Id: rfc1738.c,v 1.2 1996/02/29 08:15:23 wessels Exp $ */

#include <stdio.h>
#include <string.h>
#include "util.h"
#define BIG_BUFSIZ (BUFSIZ * 4)

/*  
 *  RFC 1738 defines that these characters should be escaped, as well
 *  any non-US-ASCII character or anything between 0x00 - 0x1F.
 */
char rfc1738_unsafe_chars[] =
{
    (char) 0x3C,		/* < */
    (char) 0x3E,		/* > */
    (char) 0x22,		/* " */
    (char) 0x23,		/* # */
    (char) 0x25,		/* % */
    (char) 0x7B,		/* { */
    (char) 0x7D,		/* } */
    (char) 0x7C,		/* | */
    (char) 0x5C,		/* \ */
    (char) 0x5E,		/* ^ */
    (char) 0x7E,		/* ~ */
    (char) 0x5B,		/* [ */
    (char) 0x5D,		/* ] */
    (char) 0x60,		/* ` */
    (char) 0x27,		/* ' */
    (char) 0x20			/* space */
};

/*
 *  rfc1738_escape - Returns a static buffer contains the RFC 1738 
 *  compliant, escaped version of the given url.
 */
char *rfc1738_escape(url)
     char *url;
{
    static char buf[BIG_BUFSIZ];
    char *p, *q;
    int i, do_escape;

    for (p = url, q = &buf[0]; *p != '\0'; p++, q++) {
	do_escape = 0;

	/* RFC 1738 defines these chars as unsafe */
	for (i = 0; i < sizeof(rfc1738_unsafe_chars); i++) {
	    if (*p == rfc1738_unsafe_chars[i]) {
		do_escape = 1;
		break;
	    }
	}
	/* RFC 1738 says any control chars (0x00-0x1F) are encoded */
	if ((*p >= (char) 0x00) && (*p <= (char) 0x1F)) {
	    do_escape = 1;
	}
	/* RFC 1738 says 0x7f is encoded */
	if (*p == (char) 0x7F) {
	    do_escape = 1;
	}
	/* RFC 1738 says any non-US-ASCII are encoded */
	if ((*p >= (char) 0x80) && (*p <= (char) 0xFF)) {
	    do_escape = 1;
	}
	/* Do the triplet encoding, or just copy the char */
	if (do_escape == 1) {
	    (void) sprintf(q, "%%%02x", (unsigned char) *p);
	    q += sizeof(char) * 2;
	} else {
	    *q = *p;
	}
    }
    *q = '\0';
    return (buf);
}

/*
 *  rfc1738_unescape() - Converts escaped characters (%xy numbers) in 
 *  given the string.  %% is a %. %ab is the 8-bit hexadecimal number "ab"
 */
void rfc1738_unescape(s)
     char *s;
{
    char hexnum[3];
    int i, j;			/* i is write, j is read */
    unsigned int x;

    for (i = j = 0; s[j]; i++, j++) {
	s[i] = s[j];
	if (s[i] == '%') {
	    hexnum[0] = s[++j];
	    if (hexnum[0] != '%') {
		hexnum[1] = s[++j];
		hexnum[2] = '\0';
		sscanf(hexnum, "%x", &x);
		s[i] = (char) (0x0ff & x);
	    } else {
		s[i] = '%';
	    }
	}
    }
    s[i] = '\0';
}
