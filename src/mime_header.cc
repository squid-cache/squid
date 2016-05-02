/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MiME Header Parsing */

#include "squid.h"

#define GET_HDR_SZ 1024
#include "Debug.h"
#include "profiler/Profiler.h"

/*
 * returns a pointer to a field-value of the first matching field-name where
 * field-value matches prefix if any
 */
char *
mime_get_header_field(const char *mime, const char *name, const char *prefix)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    const int namelen = name ? strlen(name) : 0;
    const int preflen = prefix ? strlen(prefix) : 0;
    int l;

    if (NULL == mime)
        return NULL;

    assert(NULL != name);

    debugs(25, 5, "mime_get_header: looking for '" << name << "'");

    for (p = mime; *p; p += strcspn(p, "\n\r")) {
        if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
            return NULL;

        if (strncasecmp(p, name, namelen))
            continue;

        if (!xisspace(p[namelen]) && p[namelen] != ':')
            continue;

        l = strcspn(p, "\n\r") + 1;

        if (l > GET_HDR_SZ)
            l = GET_HDR_SZ;

        xstrncpy(header, p, l);

        debugs(25, 5, "mime_get_header: checking '" << header << "'");

        q = header;

        q += namelen;

        if (*q == ':') {
            ++q;
            got = 1;
        }

        while (xisspace(*q)) {
            ++q;
            got = 1;
        }

        if (got && prefix) {
            /* we could process list entries here if we had strcasestr(). */
            /* make sure we did not match a part of another field-value */
            got = !strncasecmp(q, prefix, preflen) && !xisalpha(q[preflen]);
        }

        if (got) {
            debugs(25, 5, "mime_get_header: returning '" << q << "'");
            return q;
        }
    }

    return NULL;
}

/* returns a pointer to a field-value of the first matching field-name */
char *
mime_get_header(const char *mime, const char *name)
{
    return mime_get_header_field(mime, name, NULL);
}

size_t
headersEnd(const char *mime, size_t l)
{
    size_t e = 0;
    int state = 1;

    PROF_start(headersEnd);

    while (e < l && state < 3) {
        switch (state) {

        case 0:

            if ('\n' == mime[e])
                state = 1;

            break;

        case 1:
            if ('\r' == mime[e])
                state = 2;
            else if ('\n' == mime[e])
                state = 3;
            else
                state = 0;

            break;

        case 2:
            if ('\n' == mime[e])
                state = 3;
            else
                state = 0;

            break;

        default:
            break;
        }

        ++e;
    }
    PROF_stop(headersEnd);

    if (3 == state)
        return e;

    return 0;
}

