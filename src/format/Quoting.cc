/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "format/Quoting.h"

static const char c2x[] =
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

char *
Format::QuoteUrlEncodeUsername(const char *name)
{
    if (NULL == name)
        return NULL;

    if (name[0] == '\0')
        return NULL;

    return QuoteMimeBlob(name);
}

char *
Format::QuoteMimeBlob(const char *header)
{
    int c;
    int i;
    char *buf;
    char *buf_cursor;

    if (header == NULL) {
        buf = static_cast<char *>(xcalloc(1, 1));
        *buf = '\0';
        return buf;
    }

    buf = static_cast<char *>(xcalloc(1, (strlen(header) * 3) + 1));
    buf_cursor = buf;
    /*
     * Whe OLD_LOG_MIME is defined we escape: \x00-\x1F"#%;<>?{}|\\\\^~`\[\]\x7F-\xFF
     * which is the default escape list for the CPAN Perl5 URI module
     * modulo the inclusion of space (x40) to make the raw logs a bit
     * more readable.
     */

    while ((c = *(const unsigned char *) header++) != '\0') {
#if !OLD_LOG_MIME
        if (c == '\r') {
            *buf_cursor = '\\';
            ++buf_cursor;
            *buf_cursor = 'r';
            ++buf_cursor;
        } else if (c == '\n') {
            *buf_cursor = '\\';
            ++buf_cursor;
            *buf_cursor = 'n';
            ++buf_cursor;
        } else
#endif
            if (c <= 0x1F
                    || c >= 0x7F
                    || c == '%'
#if OLD_LOG_MIME
                    || c == '"'
                    || c == '#'
                    || c == ';'
                    || c == '<'
                    || c == '>'
                    || c == '?'
                    || c == '{'
                    || c == '}'
                    || c == '|'
                    || c == '\\'
                    || c == '^'
                    || c == '~'
                    || c == '`'
#endif
                    || c == '['
                    || c == ']') {
                *buf_cursor = '%';
                ++buf_cursor;
                i = c * 2;
                *buf_cursor = c2x[i];
                ++buf_cursor;
                *buf_cursor = c2x[i + 1];
                ++buf_cursor;
#if !OLD_LOG_MIME

            } else if (c == '\\') {
                *buf_cursor = '\\';
                ++buf_cursor;
                *buf_cursor = '\\';
                ++buf_cursor;
#endif

            } else {
                *buf_cursor = (char) c;
                ++buf_cursor;
            }
    }

    *buf_cursor = '\0';
    return buf;
}

