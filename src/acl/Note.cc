#include "squid.h"
#include "acl/Note.h"
#include "acl/HttpHeaderData.h"
#include "acl/Checklist.h"
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

