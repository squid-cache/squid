/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "sbuf/StringConvert.h"
#include "wordlist.h"

ACLNoteData::ACLNoteData() : values(new ACLStringData)
{}

ACLNoteData::~ACLNoteData()
{
    delete values;
}

bool
ACLNoteData::match(NotePairs::Entry *entry)
{
    if (entry->name().cmp(name) != 0)
        return false; // name mismatch

    // a name-only note ACL matches any value; others require a values match
    return values->empty() ||
           values->match(entry->value());
}

SBufList
ACLNoteData::dump() const
{
    SBufList sl;
    sl.push_back(name);
    sl.splice(sl.end(), values->dump());
    return sl;
}

void
ACLNoteData::parse()
{
    Acl::SetKey(name, "annotation name", ConfigParser::strtokFile());
    values->parse();
}

bool
ACLNoteData::empty() const
{
    return name.isEmpty();
}

