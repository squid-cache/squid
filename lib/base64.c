
#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

static void base64_init(void);

static int base64_initialized = 0;
int base64_value[256];
const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


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
base64_decode(const char *p)
{
    static char result[8192];
    int c;
    long val;
    int i;
    char *d;

    if (!p)
	return NULL;

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
    *d = 0;
    return *result ? result : NULL;
}

/* adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments */
const char *
base64_encode(const char *decoded_str)
{
    static char result[8192];
    int bits = 0;
    int char_count = 0;
    int out_cnt = 0;
    int c;

    if (!decoded_str)
	return decoded_str;

    if (!base64_initialized)
	base64_init();

    while ((c = *decoded_str++) && out_cnt < sizeof(result)-1) {
        bits += c;
        char_count++;
        if (char_count == 3) {
            result[out_cnt++] = base64_code[bits >> 18];
            result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = base64_code[bits & 0x3f];
            bits = 0;
            char_count = 0;
	} else {
            bits <<= 8;
	}
    }
    if (char_count != 0) {
        bits <<= 16 - (8 * char_count);
        result[out_cnt++] = base64_code[bits >> 18];
        result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
        if (char_count == 1) {
            result[out_cnt++] = '=';
            result[out_cnt++] = '=';
	} else {
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = '=';
	}
    }
    result[out_cnt] = '\0'; /* terminate */
    return result;
}
