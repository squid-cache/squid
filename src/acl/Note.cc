/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/Note.h"
#include "acl/NoteData.h"
#include "HttpRequest.h"

/* Acl::AnnotationStrategy */

const Acl::Options &
Acl::AnnotationStrategy::options()
{
    static const Acl::CharacterSetOption Delimiters;
    static const Acl::Options MyOptions = {
        { "-m", &Delimiters }
    };
    Delimiters.linkWith(&delimiters);
    return MyOptions;
}

/* ACLNoteStrategy */

int
ACLNoteStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (const auto request = checklist->request) {
        if (request->hasNotes() && matchNotes(data, request->notes().getRaw()))
            return 1;
#if USE_ADAPTATION
        const Adaptation::History::Pointer ah = request->adaptLogHistory();
        if (ah != NULL && ah->metaHeaders != NULL && matchNotes(data, ah->metaHeaders.getRaw()))
            return 1;
#endif
    }
    return 0;
}

bool
ACLNoteStrategy::matchNotes(ACLData<MatchType> *noteData, const NotePairs *note) const
{
    const NotePairs::Entries &entries = note->expandListEntries(&delimiters.value);
    for (auto e: entries)
        if (noteData->match(e.getRaw()))
            return true;
    return false;
}

