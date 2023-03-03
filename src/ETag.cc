/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ETag.h"

#include <cstring>

/*
 * Note: ETag is not an http "field" like, for example HttpHdrRange. ETag is a
 * field-value that maybe used in many http fields.
 */

/// whether etag strings match
static bool
etagStringsMatch(const ETag &tag1, const ETag &tag2)
{
    return !strcmp(tag1.str, tag2.str);
}

/* parses a string as weak or strong entity-tag; returns true on success */
/* note: we do not duplicate "str"! */
int
etagParseInit(ETag * etag, const char *str)
{
    int len;
    assert(etag && str);
    etag->str = nullptr;
    etag->weak = !strncmp(str, "W/", 2);

    if (etag->weak)
        str += 2;

    /* check format (quoted-string) */
    len = strlen(str);

    if (len >= 2 && str[0] == '"' && str[len - 1] == '"')
        etag->str = str;

    return etag->str != nullptr;
}

bool
etagIsStrongEqual(const ETag &tag1, const ETag &tag2)
{
    return !tag1.weak && !tag2.weak && etagStringsMatch(tag1, tag2);
}

bool
etagIsWeakEqual(const ETag &tag1, const ETag &tag2)
{
    return etagStringsMatch(tag1, tag2);
}

