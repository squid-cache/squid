/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_METHODDATA_H
#define SQUID_SRC_ACL_METHODDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "http/RequestMethod.h"

#include <list>

class ACLMethodData : public ACLData<HttpRequestMethod>
{
    MEMPROXY_CLASS(ACLMethodData);

public:
    ACLMethodData() {}
    ~ACLMethodData() override;
    bool match(HttpRequestMethod) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override {return values.empty();}

    std::list<HttpRequestMethod> values;

    static int ThePurgeCount; ///< PURGE methods seen by parse()
};

#endif /* SQUID_SRC_ACL_METHODDATA_H */

