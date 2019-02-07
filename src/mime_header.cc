/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MiME Header Parsing */

#include "squid.h"
#include "Debug.h"
#include "profiler/Profiler.h"

size_t
headersEnd(const char *mime, size_t l, bool &containsObsFold)
{
    size_t e = 0;
    int state = 1;
    containsObsFold = false;

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
            else if (' ' == mime[e] || '\t' == mime[e]) {
                containsObsFold = true;
                state = 0;
            } else
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

