/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREQUESTHEADERSTRATEGY_H
#define SQUID_ACLREQUESTHEADERSTRATEGY_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/ParameterizedNode.h"
#include "HttpRequest.h"

namespace Acl
{

/// matches the value of a given request header (e.g., "browser" or "referer_regex")
template <Http::HdrType header>
class RequestHeaderCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override {return true;}
};

} // namespace Acl

template <Http::HdrType header>
int
Acl::RequestHeaderCheck<header>::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    char const *theHeader = checklist->request->header.getStr(header);

    if (nullptr == theHeader)
        return 0;

    return data->match(theHeader);
}

#endif /* SQUID_REQUESTHEADERSTRATEGY_H */

