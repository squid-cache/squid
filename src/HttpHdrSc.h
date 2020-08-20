/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRSURROGATECONTROL_H
#define SQUID_HTTPHDRSURROGATECONTROL_H

#include "http/forward.h"
#include "HttpHdrScTarget.h"
#include "SquidString.h"

#include <list>

class Packable;
class StatHist;
class StoreEntry;

/* http surogate control header field */
class HttpHdrSc
{
    MEMPROXY_CLASS(HttpHdrSc);

public:
    bool parse(const String *str);
    void packInto(Packable * p) const;
    void updateStats(StatHist *) const;
    HttpHdrScTarget * getMergedTarget(const char *ourtarget); // TODO: make const?
    void setMaxAge(char const *target, int max_age);

private:
    HttpHdrScTarget * findTarget (const char *target);

    std::list<HttpHdrScTarget, PoolingAllocator<HttpHdrScTarget>> targets;
};

/* Http Surrogate Control Header Field */
void httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);
void httpHdrScInitModule (void);
HttpHdrSc *httpHdrScParseCreate(String const &);
void httpHdrScSetMaxAge(HttpHdrSc *, char const *, int);

#endif /* SQUID_HTTPHDRSURROGATECONTROL_H */

