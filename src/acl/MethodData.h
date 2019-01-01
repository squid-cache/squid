/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMETHODDATA_H
#define SQUID_ACLMETHODDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "http/RequestMethod.h"

#include <list>

class ACLMethodData : public ACLData<HttpRequestMethod>
{
    MEMPROXY_CLASS(ACLMethodData);

public:
    ACLMethodData() {}
    ACLMethodData(ACLMethodData const &);
    ACLMethodData &operator= (ACLMethodData const &);
    virtual ~ACLMethodData();
    bool match(HttpRequestMethod);
    virtual SBufList dump() const;
    void parse();
    bool empty() const {return values.empty();}
    virtual ACLData<HttpRequestMethod> *clone() const;

    std::list<HttpRequestMethod> values;

    static int ThePurgeCount; ///< PURGE methods seen by parse()
};

#endif /* SQUID_ACLMETHODDATA_H */

