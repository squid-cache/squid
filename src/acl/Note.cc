/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

/* Acl::AnnotationCheck */

const Acl::Options &
Acl::AnnotationCheck::options()
{
    static const Acl::CharacterSetOption Delimiters("-m");
    static const Acl::Options MyOptions = { &Delimiters };
    Delimiters.linkWith(&delimiters);
    return MyOptions;
}

/* Acl::NoteCheck */

int
Acl::NoteCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (const auto request = checklist->request) {
        if (request->hasNotes() && matchNotes(request->notes().getRaw()))
            return 1;
#if USE_ADAPTATION
        const Adaptation::History::Pointer ah = request->adaptLogHistory();
        if (ah != nullptr && ah->metaHeaders != nullptr && matchNotes(ah->metaHeaders.getRaw()))
            return 1;
#endif
    }
    return 0;
}

bool
Acl::NoteCheck::matchNotes(const NotePairs *note) const
{
    const NotePairs::Entries &entries = note->expandListEntries(&delimiters.value);
    for (auto e: entries)
        if (data->match(e.getRaw()))
            return true;
    return false;
}

