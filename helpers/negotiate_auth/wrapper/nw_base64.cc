/*
 * Markus Moeller has modified the following code from Squid
 */
#include "config.h"
#include "nw_base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void nw_base64_init(void);

static int base64_initialized = 0;
#define BASE64_VALUE_SZ 256
int base64_value[BASE64_VALUE_SZ];
const char base64_code[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static void
nw_base64_init(void)
{
    int i;

    for (i = 0; i < BASE64_VALUE_SZ; i++)
        base64_value[i] = -1;

    for (i = 0; i < 64; i++)
        base64_value[(int) base64_code[i]] = i;
    base64_value[(int)'='] = 0;

    base64_initialized = 1;
}

void
nw_base64_decode(char *result, const char *data, int result_size)
{
    int j;
    int c;
    long val;
    if (!data)
        return;
    if (!base64_initialized)
        nw_base64_init();
    val = c = 0;

    for (j = 0; *data; data++) {
        unsigned int k = ((unsigned char) *data) % BASE64_VALUE_SZ;
        if (base64_value[k] < 0)
            continue;
        val <<= 6;
        val += base64_value[k];
        if (++c < 4)
            continue;
        /* One quantum of four encoding characters/24 bit */
        if (j >= result_size)
            break;
        result[j++] = val >> 16;	/* High 8 bits */
        if (j >= result_size)
            break;
        result[j++] = (val >> 8) & 0xff;	/* Mid 8 bits */
        if (j >= result_size)
            break;
        result[j++] = val & 0xff;	/* Low 8 bits */
        val = c = 0;
    }
    return;
}

int
nw_base64_decode_len(const char *data)
{
    int i, j;

    j = 0;
    for (i = strlen(data) - 1; i >= 0; i--) {
        if (data[i] == '=')
            j++;
        if (data[i] != '=')
            break;
    }
    return strlen(data) / 4 * 3 - j;
}
