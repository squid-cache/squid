/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "globals.h"
#include "AccessLogEntry.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StrList.h"

#include <algorithm>
#include <string>

Note::Value::~Value()
{
    aclDestroyAclList(&aclList);
}

Note::Value::Pointer
Note::addValue(const String &value)
{
    Value::Pointer v = new Value(value);
    values.push_back(v);
    return v;
}

const char *
Note::match(HttpRequest *request, HttpReply *reply)
{

    typedef Values::iterator VLI;
    ACLFilledChecklist ch(NULL, request, NULL);
    ch.reply = reply;
    if (reply)
        HTTPMSGLOCK(ch.reply);

    for (VLI i = values.begin(); i != values.end(); ++i ) {
        const int ret= ch.fastCheck((*i)->aclList);
        debugs(93, 5, HERE << "Check for header name: " << key << ": " << (*i)->value
               <<", HttpRequest: " << request << " HttpReply: " << reply << " matched: " << ret);
        if (ret == ACCESS_ALLOWED)
            return (*i)->value.termedBuf();
    }
    return NULL;
}

Note::Pointer
Notes::add(const String &noteKey)
{
    typedef Notes::NotesList::iterator AMLI;
    for (AMLI i = notes.begin(); i != notes.end(); ++i) {
        if ((*i)->key == noteKey)
            return (*i);
    }

    Note::Pointer note = new Note(noteKey);
    notes.push_back(note);
    return note;
}

Note::Pointer
Notes::parse(ConfigParser &parser)
{
    String key, value;
    ConfigParser::ParseString(&key);
    ConfigParser::ParseQuotedString(&value);
    Note::Pointer note = add(key);
    Note::Value::Pointer noteValue = note->addValue(value);

    String label(key);
    label.append('=');
    label.append(value);
    aclParseAclList(parser, &noteValue->aclList, label.termedBuf());

    if (blacklisted) {
        for (int i = 0; blacklisted[i] != NULL; ++i) {
            if (note->key.caseCmp(blacklisted[i]) == 0) {
                fatalf("%s:%d: meta key \"%s\" is a reserved %s name",
                       cfg_filename, config_lineno, note->key.termedBuf(),
                       descr ? descr : "");
            }
        }
    }

    return note;
}

void
Notes::dump(StoreEntry *entry, const char *key)
{
    typedef Notes::NotesList::iterator AMLI;
    for (AMLI m = notes.begin(); m != notes.end(); ++m) {
        typedef Note::Values::iterator VLI;
        for (VLI v =(*m)->values.begin(); v != (*m)->values.end(); ++v ) {
            storeAppendPrintf(entry, "%s " SQUIDSTRINGPH " %s",
                              key, SQUIDSTRINGPRINT((*m)->key), ConfigParser::QuoteString((*v)->value));
            dump_acl_list(entry, (*v)->aclList);
            storeAppendPrintf(entry, "\n");
        }
    }
}

void
Notes::clean()
{
    notes.clean();
}

NotePairs::~NotePairs()
{
    while (!entries.empty())
        delete entries.pop_back();
}

const char *
NotePairs::find(const char *noteKey, const char *sep) const
{
    static String value;
    value.clean();
    for (Vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(noteKey) == 0) {
            if (value.size())
                value.append(sep);
            value.append((*i)->value);
        }
    }
    return value.size() ? value.termedBuf() : NULL;
}

const char *
NotePairs::toString(const char *sep) const
{
    static String value;
    value.clean();
    for (Vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        value.append((*i)->name);
        value.append(": ");
        value.append((*i)->value);
        value.append(sep);
    }
    return value.size() ? value.termedBuf() : NULL;
}

const char *
NotePairs::findFirst(const char *noteKey) const
{
    for (Vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(noteKey) == 0)
            return (*i)->value.termedBuf();
    }
    return NULL;
}

void
NotePairs::add(const char *key, const char *note)
{
    entries.push_back(new NotePairs::Entry(key, note));
}

void
NotePairs::remove(const char *key)
{
    Vector<NotePairs::Entry *>::iterator i = entries.begin();
    while (i != entries.end()) {
        if ((*i)->name.cmp(key) == 0) {
            NotePairs::Entry *e = (*i);
            entries.prune(e);
            delete e;
            i = entries.begin(); // vector changed underneath us
        } else
            ++i;
    }
}

void
NotePairs::addStrList(const char *key, const char *values)
{
    String strValues(values);
    const char *item;
    const char *pos = NULL;
    int ilen = 0;
    while (strListGetItem(&strValues, ',', &item, &ilen, &pos)) {
        String v;
        v.append(item, ilen);
        entries.push_back(new NotePairs::Entry(key, v.termedBuf()));
    }
}

bool
NotePairs::hasPair(const char *key, const char *value) const
{
    for (Vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(key) == 0 && (*i)->value.cmp(value) == 0)
            return true;
    }
    return false;
}

void
NotePairs::append(const NotePairs *src)
{
    for (Vector<NotePairs::Entry *>::const_iterator  i = src->entries.begin(); i != src->entries.end(); ++i) {
        entries.push_back(new NotePairs::Entry((*i)->name.termedBuf(), (*i)->value.termedBuf()));
    }
}

void
NotePairs::appendNewOnly(const NotePairs *src)
{
    for (Vector<NotePairs::Entry *>::const_iterator  i = src->entries.begin(); i != src->entries.end(); ++i) {
        if (!hasPair((*i)->name.termedBuf(), (*i)->value.termedBuf()))
            entries.push_back(new NotePairs::Entry((*i)->name.termedBuf(), (*i)->value.termedBuf()));
    }
}

NotePairs &
SyncNotes(AccessLogEntry &ale, HttpRequest &request)
{
    // XXX: auth code only has access to HttpRequest being authenticated
    // so we must handle the case where HttpRequest is set without ALE being set.

    if (!ale.notes) {
        if (!request.notes)
            request.notes = new NotePairs;
        ale.notes = request.notes;
    } else {
        assert(ale.notes == request.notes);
    }
    return *ale.notes;
}
