/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Copied from Nettle 3.4 under GPLv2, with adjustments
 */

#include "squid.h"
#include "base64.h"

#if !HAVE_NETTLE_BASE64_H || !HAVE_NETTLE34_BASE64

/* base64-encode.c

   Copyright (C) 2002 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#define TABLE_INVALID -1
#define TABLE_SPACE -2
#define TABLE_END -3

void
base64_decode_init(struct base64_decode_ctx *ctx)
{
    static const signed char base64_decode_table[0x100] =
    {
        /* White space is HT, VT, FF, CR, LF and SPC */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -2, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    ctx->word = ctx->bits = ctx->padding = 0;
    ctx->table = base64_decode_table;
}

int
base64_decode_single(struct base64_decode_ctx *ctx,
                     uint8_t *dst,
                     char src)
{
    int data = ctx->table[(uint8_t) src];

    switch(data)
    {
    default:
        assert(data >= 0 && data < 0x40);

        if (ctx->padding)
            return -1;

        ctx->word = ctx->word << 6 | data;
        ctx->bits += 6;

        if (ctx->bits >= 8)
        {
            ctx->bits -= 8;
            dst[0] = ctx->word >> ctx->bits;
            return 1;
        }
        else return 0;

    case TABLE_INVALID:
        return -1;

    case TABLE_SPACE:
        return 0;

    case TABLE_END:
        /* There can be at most two padding characters. */
        if (!ctx->bits || ctx->padding > 2)
            return -1;

        if (ctx->word & ( (1<<ctx->bits) - 1))
            /* We shouldn't have any leftover bits */
            return -1;

        ctx->padding++;
        ctx->bits -= 2;
        return 0;
    }
}

int
base64_decode_update(struct base64_decode_ctx *ctx,
                     size_t *dst_length,
                     uint8_t *dst,
                     size_t src_length,
                     const char *src)
{
    size_t done;
    size_t i;

    for (i = 0, done = 0; i<src_length; i++)
        switch(base64_decode_single(ctx, dst + done, src[i]))
        {
        case -1:
            return 0;
        case 1:
            done++;
        /* Fall through */
        case 0:
            break;
        default:
            abort();
        }

    assert(done <= BASE64_DECODE_LENGTH(src_length));

    *dst_length = done;
    return 1;
}

int
base64_decode_final(struct base64_decode_ctx *ctx)
{
    return ctx->bits == 0;
}

/* base64-encode.c */

#define ENCODE(alphabet,x) ((alphabet)[0x3F & (x)])

static void
encode_raw(const char *alphabet,
           char *dst, size_t length, const uint8_t *src)
{
    const uint8_t *in = src + length;
    char *out = dst + BASE64_ENCODE_RAW_LENGTH(length);

    unsigned left_over = length % 3;

    if (left_over)
    {
        in -= left_over;
        *--out = '=';
        switch(left_over)
        {
        case 1:
            *--out = '=';
            *--out = ENCODE(alphabet, (in[0] << 4));
            break;

        case 2:
            *--out = ENCODE(alphabet, (in[1] << 2));
            *--out = ENCODE(alphabet, ((in[0] << 4) | (in[1] >> 4)));
            break;

        default:
            abort();
        }
        *--out = ENCODE(alphabet, (in[0] >> 2));
    }

    while (in > src)
    {
        in -= 3;
        *--out = ENCODE(alphabet, (in[2]));
        *--out = ENCODE(alphabet, ((in[1] << 2) | (in[2] >> 6)));
        *--out = ENCODE(alphabet, ((in[0] << 4) | (in[1] >> 4)));
        *--out = ENCODE(alphabet, (in[0] >> 2));
    }
    assert(in == src);
    assert(out == dst);
}

static const char base64_encode_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

void
base64_encode_raw(char *dst, size_t length, const uint8_t *src)
{
    encode_raw(base64_encode_table, dst, length, src);
}

void
base64_encode_group(char *dst, uint32_t group)
{
    *dst++ = ENCODE(base64_encode_table, (group >> 18));
    *dst++ = ENCODE(base64_encode_table, (group >> 12));
    *dst++ = ENCODE(base64_encode_table, (group >> 6));
    *dst++ = ENCODE(base64_encode_table, group);
}

void
base64_encode_init(struct base64_encode_ctx *ctx)
{
    ctx->word = ctx->bits = 0;
    ctx->alphabet = base64_encode_table;
}

/* Encodes a single byte. */
size_t
base64_encode_single(struct base64_encode_ctx *ctx,
                     char *dst,
                     uint8_t src)
{
    unsigned done = 0;
    unsigned word = ctx->word << 8 | src;
    unsigned bits = ctx->bits + 8;

    while (bits >= 6)
    {
        bits -= 6;
        dst[done++] = ENCODE(ctx->alphabet, (word >> bits));
    }

    ctx->bits = bits;
    ctx->word = word;

    assert(done <= 2);

    return done;
}

/* Returns the number of output characters. DST should point to an
 * area of size at least BASE64_ENCODE_LENGTH(length). */
size_t
base64_encode_update(struct base64_encode_ctx *ctx,
                     char *dst,
                     size_t length,
                     const uint8_t *src)
{
    size_t done = 0;
    size_t left = length;
    unsigned left_over;
    size_t bulk;

    while (ctx->bits && left)
    {
        left--;
        done += base64_encode_single(ctx, dst + done, *src++);
    }

    left_over = left % 3;
    bulk = left - left_over;

    if (bulk)
    {
        assert(!(bulk % 3));

        encode_raw(ctx->alphabet, dst + done, bulk, src);
        done += BASE64_ENCODE_RAW_LENGTH(bulk);
        src += bulk;
        left = left_over;
    }

    while (left)
    {
        left--;
        done += base64_encode_single(ctx, dst + done, *src++);
    }

    assert(done <= BASE64_ENCODE_LENGTH(length));

    return done;
}

/* DST should point to an area of size at least
 * BASE64_ENCODE_FINAL_SIZE */
size_t
base64_encode_final(struct base64_encode_ctx *ctx,
                    char *dst)
{
    unsigned done = 0;
    unsigned bits = ctx->bits;

    if (bits)
    {
        dst[done++] = ENCODE(ctx->alphabet, (ctx->word << (6 - ctx->bits)));
        for (; bits < 6; bits += 2)
            dst[done++] = '=';

        ctx->bits = 0;
    }

    assert(done <= BASE64_ENCODE_FINAL_LENGTH);
    return done;
}

#endif /* !HAVE_NETTLE_BASE64_H || !HAVE_NETTLE34_BASE64 */

