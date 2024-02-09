/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TIMEORTAG_H
#define SQUID_SRC_TIMEORTAG_H

#include "ETag.h"

/**
 * Some fields can hold either time or etag specs (e.g. If-Range)
 */
class TimeOrTag
{
public:
    ETag tag;                   /* entity tag */
    time_t time;
    int valid;                  /* true if struct is usable */
};

#endif /* SQUID_SRC_TIMEORTAG_H */

