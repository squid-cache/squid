/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMETHODDATA_H
#define SQUID_ACLMETHODDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "CbDataList.h"
#include "HttpRequestMethod.h"

/// \ingroup ACLAPI
class ACLMethodData : public ACLData<HttpRequestMethod>
{

public:
    MEMPROXY_CLASS(ACLMethodData);

    ACLMethodData();
    ACLMethodData(ACLMethodData const &);
    ACLMethodData &operator= (ACLMethodData const &);
    virtual ~ACLMethodData();
    bool match(HttpRequestMethod);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<HttpRequestMethod> *clone() const;

    CbDataList<HttpRequestMethod> *values;

    static int ThePurgeCount; ///< PURGE methods seen by parse()
};

MEMPROXY_CLASS_INLINE(ACLMethodData);

#endif /* SQUID_ACLMETHODDATA_H */

