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
#include "acl/NoteData.h"
#include "HttpRequest.h"
#include "Notes.h"
#include "parser/Tokenizer.h"
#include "sbuf/StringConvert.h"

int
ACLNoteStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &flags)
{
    if (const auto request = checklist->request) {
        if (request->notes != NULL && matchNotes(data, request->notes.getRaw(), flags.delimiters()))
            return 1;
#if USE_ADAPTATION
        const Adaptation::History::Pointer ah = request->adaptLogHistory();
        if (ah != NULL && ah->metaHeaders != NULL && matchNotes(data, ah->metaHeaders.getRaw(), flags.delimiters()))
            return 1;
#endif
    }
    return 0;
}

bool
ACLNoteStrategy::matchNotes(ACLData<MatchType> *noteData, const NotePairs *note, const CharacterSet *delimiters) const
{
    for (auto &entry: note->entries) {
        if (delimiters) {
            NotePairs::Entry e(entry->name.termedBuf(), "");
            Parser::Tokenizer t(StringToSBuf(entry->value));
            SBuf s;
            while (t.token(s, *delimiters)) {
                e.value = s.c_str();
                if (noteData->match(&e))
                    return true;
            }
            s = t.remaining();
            e.value = s.c_str();
            if (noteData->match(&e))
                return true;
        }
        if (noteData->match(entry))
            return true;
    }
    return false;
}

ACLNoteStrategy *
ACLNoteStrategy::Instance()
{
    return &Instance_;
}

ACLNoteStrategy ACLNoteStrategy::Instance_;

