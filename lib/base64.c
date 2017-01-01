/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Encoders adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments.
 */

#include "squid.h"
#include "base64.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

static void base64_init(void);

static int base64_initialized = 0;
#define BASE64_VALUE_SZ 256
#define BASE64_RESULT_SZ 8192
int base64_value[BASE64_VALUE_SZ];
const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
base64_init(void)
{
    int i;

    for (i = 0; i < BASE64_VALUE_SZ; i++)
        base64_value[i] = -1;

    for (i = 0; i < 64; i++)
        base64_value[(int) base64_code[i]] = i;
    base64_value['='] = 0;

    base64_initialized = 1;
}

int
base64_decode_len(const char *data)
{
    if (!data || !*data)
        return 0;

    int terminatorLen = 0;
    int dataLen = strlen(data);
    int i;

    for (i = dataLen - 1; i >= 0; i--) {
        if (data[i] == '=')
            terminatorLen++;
        if (data[i] != '=')
            break;
    }
    return dataLen / 4 * 3 - terminatorLen;
}

int
base64_decode(char *result, unsigned int result_size, const char *p)
{
    int j = 0;
    int c;
    long val;
    if (!p || !result || result_size == 0)
        return j;
    if (!base64_initialized)
        base64_init();
    val = c = 0;
    for (; *p; p++) {
        unsigned int k = ((unsigned char) *p) % BASE64_VALUE_SZ;
        if (base64_value[k] < 0)
            continue;
        val <<= 6;
        val += base64_value[k];
        if (++c < 4)
            continue;
        /* One quantum of four encoding characters/24 bit */
        if (j+4 <= result_size) {
            // Speed optimization: plenty of space, avoid some per-byte checks.
            result[j++] = (val >> 16) & 0xff;   /* High 8 bits */
            result[j++] = (val >> 8) & 0xff;    /* Mid 8 bits */
            result[j++] = val & 0xff;       /* Low 8 bits */
        } else {
            // part-quantum goes a bit slower with per-byte checks
            result[j++] = (val >> 16) & 0xff;   /* High 8 bits */
            if (j == result_size)
                return j;
            result[j++] = (val >> 8) & 0xff;    /* Mid 8 bits */
            if (j == result_size)
                return j;
            result[j++] = val & 0xff;       /* Low 8 bits */
        }
        if (j == result_size)
            return j;
        val = c = 0;
    }
    return j;
}

int
base64_encode_len(int len)
{
    // NP: some magic numbers + potential nil-terminator
    return ((len + 2) / 3 * 4) + 1;
}

const char *
old_base64_encode(const char *decoded_str)
{
    static char result[BASE64_RESULT_SZ];
    base64_encode_str(result, sizeof(result), decoded_str, strlen(decoded_str));
    return result;
}

const char *
base64_encode_bin(const char *decoded_str, int len)
{
    static char result[BASE64_RESULT_SZ];
    base64_encode_str(result, sizeof(result), decoded_str, len);
    return result;
}

int
base64_encode_str(char *result, int result_max_size, const char *data, int data_size)
{
    if (result_max_size < 1)
        return 0;

    int used = base64_encode(result, result_max_size, data, data_size);
    /* terminate */
    if (used >= result_max_size) {
        result[result_max_size - 1] = '\0';
        return result_max_size;
    } else {
        result[used++] = '\0';
    }
    return used;
}

/* adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments */
int
base64_encode(char *result, int result_size, const char *data, int data_size)
{
    int bits = 0;
    int char_count = 0;
    int out_cnt = 0;

    if (!data || !result || result_size < 1 || data_size < 1)
        return 0;

    if (!base64_initialized)
        base64_init();

    while (data_size--) {
        int c = (unsigned char) *data++;
        bits += c;
        char_count++;
        if (char_count == 3) {
            if (out_cnt >= result_size)
                break;
            if (out_cnt+4 <= result_size) {
                result[out_cnt++] = base64_code[bits >> 18];
                result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
                result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
                result[out_cnt++] = base64_code[bits & 0x3f];
            } else {
                // part-quantum goes a bit slower with per-byte checks
                result[out_cnt++] = base64_code[bits >> 18];
                if (out_cnt >= result_size)
                    break;
                result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
                if (out_cnt >= result_size)
                    break;
                result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
                if (out_cnt >= result_size)
                    break;
                result[out_cnt++] = base64_code[bits & 0x3f];
            }
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 8;
        }
    }
    if (char_count != 0) {
        bits <<= 16 - (8 * char_count);
        if (out_cnt >= result_size)
            return result_size;
        result[out_cnt++] = base64_code[bits >> 18];
        if (out_cnt >= result_size)
            return result_size;
        result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
        if (char_count == 1) {
            if (out_cnt >= result_size)
                return result_size;
            result[out_cnt++] = '=';
            if (out_cnt >= result_size)
                return result_size;
            result[out_cnt++] = '=';
        } else {
            if (out_cnt >= result_size)
                return result_size;
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            if (out_cnt >= result_size)
                return result_size;
            result[out_cnt++] = '=';
        }
    }
    return (out_cnt >= result_size?result_size:out_cnt);
}

