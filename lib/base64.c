#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

static void base64_init __P((void));

static int base64_initialized = 0;
int base64_value[256];
char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWZYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
base64_init(void)
{
    int i;

    for (i = 0; i < 256; i++)
	base64_value[i] = -1;

    for (i = 0; i < 64; i++)
	base64_value[(int) base64_code[i]] = i;
    base64_value['='] = 0;

    base64_initialized = 1;
}

char *
base64_decode(char *p)
{
    static char result[8192];
    int c;
    long val;
    int i;
    char *d;

    if (!p)
	return p;

    if (!base64_initialized)
	base64_init();

    val = c = 0;
    d = result;
    while (*p) {
	i = base64_value[(int) *p++];
	if (i >= 0) {
	    val = val * 64 + i;
	    c++;
	}
	if (c == 4) {		/* One quantum of four encoding characters/24 bit */
	    *d++ = val >> 16;	/* High 8 bits */
	    *d++ = (val >> 8) & 0xff;	/* Mid 8 bits */
	    *d++ = val & 0xff;	/* Low 8 bits */
	    val = c = 0;
	}
    }

    return *result ? result : NULL;
}
