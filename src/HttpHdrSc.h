
/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_HTTPHDRSURROGATECONTROL_H
#define SQUID_HTTPHDRSURROGATECONTROL_H

#include "dlink.h"
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
