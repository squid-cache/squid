/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRSURROGATECONTROL_H
#define SQUID_HTTPHDRSURROGATECONTROL_H

#include "dlink.h"
#include "mem/forward.h"
#include "SquidString.h"

class HttpHdrScTarget;
class Packable;
class StatHist;
class StoreEntry;

typedef enum {
    SC_NO_STORE,
    SC_NO_STORE_REMOTE,
    SC_MAX_AGE,
    SC_CONTENT,
    SC_OTHER,
    SC_ENUM_END /* also used to mean "invalid" */
} http_hdr_sc_type;

/* http surogate control header field */
class HttpHdrSc
{
    MEMPROXY_CLASS(HttpHdrSc);

public:
    HttpHdrSc(const HttpHdrSc &);
    HttpHdrSc() {}
    ~HttpHdrSc();

    bool parse(const String *str);
    void packInto(Packable * p) const;
    void updateStats(StatHist *) const;
    HttpHdrScTarget * getMergedTarget(const char *ourtarget); // TODO: make const?
    void setMaxAge(char const *target, int max_age);
    void addTarget(HttpHdrScTarget *t);
    void addTargetAtTail(HttpHdrScTarget *t);

    dlink_list targets;
private:
    HttpHdrScTarget * findTarget (const char *target);

};

/* Http Surrogate Control Header Field */
void httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);
void httpHdrScInitModule (void);
HttpHdrSc *httpHdrScParseCreate(String const &);
void httpHdrScSetMaxAge(HttpHdrSc *, char const *, int);

#endif /* SQUID_HTTPHDRSURROGATECONTROL_H */

