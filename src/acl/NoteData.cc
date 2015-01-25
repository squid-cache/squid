/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/NoteData.h"
#include "acl/StringData.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "HttpRequest.h"
#include "Notes.h"
#include "wordlist.h"

ACLNoteData::ACLNoteData() : values(new ACLStringData)
{}

ACLNoteData::~ACLNoteData()
{
    delete values;
}

bool
ACLNoteData::matchNotes(NotePairs *note)
{
    if (note == NULL)
        return false;

    debugs(28, 3, "Checking " << name);

    if (values->empty())
        return (note->findFirst(name.termedBuf()) != NULL);

    for (std::vector<NotePairs::Entry *>::iterator i = note->entries.begin(); i!= note->entries.end(); ++i) {
        if ((*i)->name.cmp(name.termedBuf()) == 0) {
            if (values->match((*i)->value.termedBuf()))
                return true;
        }
    }
    return false;
}

bool
ACLNoteData::match(HttpRequest *request)
{
    if (request->notes != NULL && matchNotes(request->notes.getRaw()))
        return true;
#if USE_ADAPTATION
    const Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL && ah->metaHeaders != NULL && matchNotes(ah->metaHeaders.getRaw()))
        return true;
#endif
    return false;
}

SBufList
ACLNoteData::dump() const
{
    SBufList sl;
    sl.push_back(SBuf(name));
#if __cplusplus >= 201103L
    sl.splice(sl.end(), values->dump());
#else
    // temp is needed until c++11 move constructor
    SBufList temp = values->dump();
    sl.splice(sl.end(), temp);
#endif
    return sl;
}

void
ACLNoteData::parse()
{
    char* t = strtokFile();
    assert (t != NULL);
    name = t;
    values->parse();
}

bool
ACLNoteData::empty() const
{
    return name.size() == 0;
}

ACLData<HttpRequest *> *
ACLNoteData::clone() const
{
    ACLNoteData * result = new ACLNoteData;
    result->values = values->clone();
    result->name = name;
    return result;
}

