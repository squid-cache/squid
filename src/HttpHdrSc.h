/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRSURROGATECONTROL_H
#define SQUID_HTTPHDRSURROGATECONTROL_H

#include "HttpHdrScTarget.h"

class StatHist;

/* http surogate control header field */

class HttpHdrSc
{

public:
    HttpHdrSc(const HttpHdrSc &);
    HttpHdrSc() {}
    ~HttpHdrSc();

    bool parse(const String *str);
    void packInto(Packer * p) const;
    void updateStats(StatHist *) const;
    HttpHdrScTarget * getMergedTarget (const char *ourtarget); //todo: make const?
    void setMaxAge(char const *target, int max_age);
    void addTarget(HttpHdrScTarget *t) {
        dlinkAdd(t, &t->node, &targets);
    }
    void addTargetAtTail(HttpHdrScTarget *t) {
        dlinkAddTail (t, &t->node, &targets);
    }

    MEMPROXY_CLASS(HttpHdrSc);
    dlink_list targets;
private:
    HttpHdrScTarget * findTarget (const char *target);

};

MEMPROXY_CLASS_INLINE(HttpHdrSc);

/* Http Surrogate Control Header Field */
void httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);
void httpHdrScInitModule (void);
void httpHdrScCleanModule (void);
HttpHdrSc *httpHdrScParseCreate(String const &);
void httpHdrScSetMaxAge(HttpHdrSc *, char const *, int);

#endif /* SQUID_HTTPHDRSURROGATECONTROL_H */

