/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_AUTH

#include "acl/ExtUser.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
#include "http/Stream.h"

ACLExtUser::~ACLExtUser()
{
    delete data;
}

ACLExtUser::ACLExtUser(ACLData<char const *> *newData, char const *newType) : data (newData), type_ (newType) {}

char const *
ACLExtUser::typeString() const
{
    return type_;
}

const Acl::Options &
ACLExtUser::lineOptions()
{
    return data->lineOptions();
}

void
ACLExtUser::parse()
{
    data->parse();
}

int
ACLExtUser::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    if (checklist->request->extacl_user.size()) {
        return data->match(checklist->request->extacl_user.termedBuf());
    } else {
        return -1;
    }
}

SBufList
ACLExtUser::dump() const
{
    return data->dump();
}

bool
ACLExtUser::empty () const
{
    return data->empty();
}

#endif /* USE_AUTH */

