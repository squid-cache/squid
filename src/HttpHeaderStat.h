/*
 * HttpHeaderStat.h
 *
 *  Created on: Dec 9, 2011
 *      Author: kinkie
 */

#ifndef HTTPHEADERSTAT_H_
#define HTTPHEADERSTAT_H_

/* per header statistics */

#include "StatHist.h"
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
