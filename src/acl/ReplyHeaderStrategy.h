/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREPLYHEADERSTRATEGY_H
#define SQUID_ACLREPLYHEADERSTRATEGY_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/ParameterizedNode.h"
#include "acl/ReplyHeaderStrategy.h"
#include "HttpReply.h"

namespace Acl
{

/// matches the value of a given reply header (e.g., "rep_mime_type" ACL)
template <Http::HdrType header>
class ReplyHeaderCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresReply() const override {return true;}
};

} // namespace Acl

template <Http::HdrType header>
int
Acl::ReplyHeaderCheck<header>::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    char const *theHeader = checklist->reply->header.getStr(header);

    if (nullptr == theHeader)
        return 0;

    return data->match(theHeader);
}

#endif /* SQUID_REPLYHEADERSTRATEGY_H */

