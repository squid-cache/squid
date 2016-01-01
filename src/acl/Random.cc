/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Random.h"
#include "Debug.h"
#include "Parsing.h"
#include "wordlist.h"

#include <random>

ACL *
ACLRandom::clone() const
{
    return new ACLRandom(*this);
}

ACLRandom::ACLRandom(char const *theClass) : data(0.0), class_(theClass)
{
    memset(pattern, 0 , sizeof(pattern));
}

ACLRandom::ACLRandom(ACLRandom const & old) : data(old.data), class_(old.class_)
{
    memcpy(pattern, old.pattern, sizeof(pattern));
}

ACLRandom::~ACLRandom()
{ }

char const *
ACLRandom::typeString() const
{
    return class_;
}

bool
ACLRandom::empty () const
{
    return data == 0.0;
}

bool
ACLRandom::valid() const
{
    return !empty();
}

/*******************/
/* aclParseRandomList */
/*******************/
void
ACLRandom::parse()
{
    char bufa[256], bufb[256];

    char *t = ConfigParser::strtokFile();
    if (!t) {
        debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "ACL random missing pattern");
        return;
    }

    debugs(28, 5, "aclParseRandomData: " << t);

    // seed random generator ...
    srand(time(NULL));

    if (sscanf(t, "%[0-9]:%[0-9]", bufa, bufb) == 2) {
        int a = xatoi(bufa);
        int b = xatoi(bufb);
        if (a <= 0 || b <= 0) {
            debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
            return;
        } else
            data = a / (double)(a+b);
    } else if (sscanf(t, "%[0-9]/%[0-9]", bufa, bufb) == 2) {
        int a = xatoi(bufa);
        int b = xatoi(bufb);
        if (a <= 0 || b <= 0 || a > b) {
            debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
            return;
        } else
            data = (double) a / (double) b;
    } else if (sscanf(t, "0.%[0-9]", bufa) == 1) {
        data = atof(t);
    } else {
        debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
        return;
    }

    // save the exact input pattern. so we can display it later.
    memcpy(pattern, t, min(sizeof(pattern)-1,strlen(t)));
}

int
ACLRandom::match(ACLChecklist *)
{
    // make up the random value.
    // The fixed-value default seed is fine because we are
    // actually matching whether the random value is above
    // or below the configured threshold ratio.
    static std::mt19937 mt;
    static xuniform_real_distribution<> dist(0, 1);

    const double random = dist(mt);

    debugs(28, 3, "ACL Random: " << name << " " << pattern << " test: " << data << " > " << random << " = " << ((data > random)?"MATCH":"NO MATCH") );
    return (data > random)?1:0;
}

SBufList
ACLRandom::dump() const
{
    SBufList sl;
    sl.push_back(SBuf(pattern));
    return sl;
}

