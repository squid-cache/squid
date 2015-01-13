/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef HTTPHEADERSTAT_H_
#define HTTPHEADERSTAT_H_

#include "StatHist.h"

/// per header statistics
class HttpHeaderStat
{
public:
    const char *label;
    HttpHeaderMask *owner_mask;

    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
    StatHist scTypeDistr;

    int parsedCount;
    int ccParsedCount;
    int scParsedCount;
    int destroyedCount;
    int busyDestroyedCount;
};

#endif /* HTTPHEADERSTAT_H_ */

