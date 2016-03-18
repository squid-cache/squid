/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLATSTEPDATA_H
#define SQUID_ACLATSTEPDATA_H

#if USE_OPENSSL

#include "acl/Acl.h"
#include "acl/Data.h"
#include "ssl/support.h"

#include <list>

class ACLAtStepData : public ACLData<Ssl::BumpStep>
{
    MEMPROXY_CLASS(ACLAtStepData);

public:
    ACLAtStepData();
    ACLAtStepData(ACLAtStepData const &);
    ACLAtStepData &operator= (ACLAtStepData const &);
    virtual ~ACLAtStepData();
    bool match(Ssl::BumpStep);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLAtStepData *clone() const;

    std::list<Ssl::BumpStep> values;
};

#endif /* USE_OPENSSL */

#endif /* SQUID_ACLSSL_ERRORDATA_H */

