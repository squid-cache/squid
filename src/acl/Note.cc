/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/Note.h"
#include "HttpRequest.h"
#include "Notes.h"

int
ACLNoteStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (checklist->request != NULL)
        return data->match(checklist->request);

    return 0;
}

ACLNoteStrategy *
ACLNoteStrategy::Instance()
{
    return &Instance_;
}

ACLNoteStrategy ACLNoteStrategy::Instance_;

